//go:build amd64 || arm64

package loader

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/drops"
	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

var (
	ErrLibSSLNotExecutable = errors.New("libssl path has no execute permission bit set (try: sudo chmod +x <path>)")
	ErrSSLRegistryClosed   = errors.New("SSL registry is closed")
)

// requiredSSLSymbols must resolve for a libssl file to be usable — tls.Find
// already guarantees these exist before a pid is ever handed to Shared, so
// failure here means the discovering pid and the shared registry disagree
// about the file at libsslPath.
var requiredSSLSymbols = []string{"SSL_set_fd", "SSL_write", "SSL_read", "SSL_free"}

// optionalSSLSymbols are attached when present; some libssl builds omit them.
var optionalSSLSymbols = []string{"SSL_write_ex", "SSL_read_ex"}

func checkLibSSLExecutable(libsslPath string) error {
	info, err := os.Stat(libsslPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", libsslPath, err)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("%s: %w", libsslPath, ErrLibSSLNotExecutable)
	}
	return nil
}

// SSLObjectsKey identifies one physical libssl file by (device, inode) — the
// same physical file is reachable through many pid-namespaced paths of the
// form /proc/<pid>/root/..., so identity has to be recovered via stat rather
// than by comparing paths.
type SSLObjectsKey struct{ dev, ino uint64 }

func sslObjectsKeyFor(libsslPath string) (SSLObjectsKey, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(libsslPath, &st); err != nil {
		return SSLObjectsKey{}, fmt.Errorf("stat %s: %w", libsslPath, err)
	}
	return SSLObjectsKey{dev: uint64(st.Dev), ino: st.Ino}, nil
}

// SSLObjects is the BPF program and map set for one physical libssl file,
// shared by every pid that maps it (#327): one ssl_fd_map, one
// drop_counters, one ssl_events ring and the Reader draining it. Loaded once
// per (dev, inode) by SSLRegistry.Shared and kept for the registry's
// lifetime — per-pid state is only the uprobe links in SSLLinks.
type SSLObjects struct {
	key     SSLObjectsKey
	objs    bpf.TinytapUprobeObjects
	Reader  *ringbuf.Reader
	offsets map[string]uint64 // symbol name -> ELF file offset, resolved once
}

func (o *SSLObjects) Lookup(pid uint32, ssl uint64) (int32, bool) {
	key := bpf.TinytapUprobeSslFdKey{Pid: pid, Ssl: ssl}
	var fd int32
	if err := o.objs.SslFdMap.Lookup(&key, &fd); err != nil {
		return 0, false
	}
	return fd, true
}

func (o *SSLObjects) Delete(pid uint32, ssl uint64) {
	key := bpf.TinytapUprobeSslFdKey{Pid: pid, Ssl: ssl}
	_ = o.objs.SslFdMap.Delete(&key)
}

// DeletePids removes every ssl_fd_map entry belonging to a pid in dead. The
// map is shared across every pid attached to this libssl file, so a pid that
// exits without calling SSL_free would otherwise never be reclaimed (#327) —
// callers pass the reaper's dead-pid set once per reap tick.
func (o *SSLObjects) DeletePids(dead map[uint32]bool) int {
	if len(dead) == 0 {
		return 0
	}
	var (
		key   bpf.TinytapUprobeSslFdKey
		val   int32
		stale []bpf.TinytapUprobeSslFdKey
	)
	it := o.objs.SslFdMap.Iterate()
	for it.Next(&key, &val) {
		if dead[key.Pid] {
			stale = append(stale, key)
		}
	}
	for i := range stale {
		_ = o.objs.SslFdMap.Delete(&stale[i])
	}
	return len(stale)
}

func (o *SSLObjects) DropCounts() drops.Counts {
	if o.objs.DropCounters == nil {
		return drops.Counts{}
	}
	return readDrops(o.objs.DropCounters)
}

func (o *SSLObjects) Close() error {
	var errs []error
	if o.Reader != nil {
		if err := o.Reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close ssl ringbuf: %w", err))
		}
	}
	if err := o.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close uprobe objects: %w", err))
	}
	return errors.Join(errs...)
}

// SSLLinks is one pid's uprobe attachment against a shared SSLObjects. A nil
// *SSLLinks is a valid, already-closed value so callers can store it
// unconditionally when an attach fails partway (e.g. #147's "keep the
// SSL_set_fd link when the payload attach fails").
type SSLLinks struct{ links []link.Link }

func (l *SSLLinks) Close() error {
	if l == nil {
		return nil
	}
	var errs []error
	for _, lnk := range l.links {
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close uprobe link: %w", err))
		}
	}
	return errors.Join(errs...)
}

// SSLRegistry caches SSLObjects by (dev, inode) so every pid mapping the
// same libssl file shares one set of BPF programs, maps, and ringbuf reader
// instead of each pid loading its own (#327). Objects are loaded lazily and
// live for the registry's lifetime — a host has a handful of distinct
// libssl files, so there is no eviction, only Close at shutdown.
type SSLRegistry struct {
	mu     sync.Mutex
	closed bool
	sets   map[SSLObjectsKey]*SSLObjects
}

func NewSSLRegistry() *SSLRegistry {
	return &SSLRegistry{sets: make(map[SSLObjectsKey]*SSLObjects)}
}

// Shared returns the SSLObjects for the libssl file at libsslPath, loading
// it on the first call for that (dev, inode). created is true only for the
// single caller that performed the load, so the caller knows to start
// exactly one reader loop over obj.Reader. On error nothing is cached, so a
// transient failure (e.g. a race with the file being replaced) is retried by
// the next caller rather than being pinned forever.
func (r *SSLRegistry) Shared(libsslPath string) (obj *SSLObjects, created bool, err error) {
	if err := checkLibSSLExecutable(libsslPath); err != nil {
		return nil, false, err
	}
	key, err := sslObjectsKeyFor(libsslPath)
	if err != nil {
		return nil, false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, false, ErrSSLRegistryClosed
	}
	if obj, ok := r.sets[key]; ok {
		return obj, false, nil
	}

	obj, err = loadSSLObjects(key, libsslPath)
	if err != nil {
		return nil, false, err
	}
	r.sets[key] = obj
	return obj, true, nil
}

func (r *SSLRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	var errs []error
	for _, obj := range r.sets {
		if err := obj.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	r.sets = nil
	return errors.Join(errs...)
}

func loadSSLObjects(key SSLObjectsKey, libsslPath string) (*SSLObjects, error) {
	offsets, err := resolveSymbolOffsets(libsslPath, append(append([]string{}, requiredSSLSymbols...), optionalSSLSymbols...))
	if err != nil {
		return nil, fmt.Errorf("resolve symbols in %s: %w", libsslPath, err)
	}
	for _, sym := range requiredSSLSymbols {
		if _, ok := offsets[sym]; !ok {
			return nil, fmt.Errorf("%s: required symbol %s: %w", libsslPath, sym, link.ErrNoSymbol)
		}
	}

	spec, err := bpf.LoadTinytapUprobe()
	if err != nil {
		return nil, fmt.Errorf("load uprobe spec: %w", err)
	}

	o := &SSLObjects{key: key, offsets: offsets}
	if err := spec.LoadAndAssign(&o.objs, nil); err != nil {
		return nil, fmt.Errorf("load uprobe objects: %w", err)
	}

	rd, err := ringbuf.NewReader(o.objs.SslEvents)
	if err != nil {
		_ = o.objs.Close()
		return nil, fmt.Errorf("open ssl ringbuf: %w", err)
	}
	o.Reader = rd

	return o, nil
}

// resolveSymbolOffsets parses the ELF (regular and dynamic) symbol tables of
// path once and returns the file offset of every requested function symbol
// that is present. It mirrors cilium/ebpf's internal Executable.load, which
// is not exported: a symbol's uprobe attach point is its virtual address
// translated into the containing executable PT_LOAD segment's file offset
// (fn offset = fn VA - segment VA + segment file offset).
//
// This is what lets AttachSSLSetFd/AttachSSLReadWrite open a fresh
// *link.Executable per pid (cheap: just a stat, since UprobeOptions.Address
// bypasses ELF parsing) instead of reusing one *link.Executable — and thus
// one pid's /proc/<pid>/root/... path — across every pid on the same libssl
// inode, which would break the moment the pid that first resolved it exits.
func resolveSymbolOffsets(path string, symbols []string) (map[string]uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ELF: %w", err)
	}
	defer func() { _ = f.Close() }()

	want := make(map[string]bool, len(symbols))
	for _, s := range symbols {
		want[s] = true
	}

	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("read symbols: %w", err)
	}
	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("read dynamic symbols: %w", err)
	}

	offsets := make(map[string]uint64, len(symbols))
	for _, s := range append(syms, dynsyms...) {
		if !want[s.Name] || elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		if _, ok := offsets[s.Name]; ok {
			continue
		}
		offsets[s.Name] = symbolFileOffset(f, s)
	}
	return offsets, nil
}

func symbolFileOffset(f *elf.File, s elf.Symbol) uint64 {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		if prog.Vaddr <= s.Value && s.Value < prog.Vaddr+prog.Memsz {
			return s.Value - prog.Vaddr + prog.Off
		}
	}
	return s.Value
}

// AttachSSLSetFd attaches the SSL_set_fd uprobe for pid against the shared
// obj's programs, using pid's own live libsslPath so the kernel registers
// the breakpoint against a path that is actually resolvable right now.
func AttachSSLSetFd(obj *SSLObjects, pid uint32, libsslPath string) (*SSLLinks, error) {
	if err := checkLibSSLExecutable(libsslPath); err != nil {
		return nil, err
	}
	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		return nil, fmt.Errorf("open executable %s: %w", libsslPath, err)
	}

	offset, ok := obj.offsets["SSL_set_fd"]
	if !ok {
		return nil, fmt.Errorf("attach uprobe SSL_set_fd: %w", link.ErrNoSymbol)
	}
	lnk, err := ex.Uprobe("SSL_set_fd", obj.objs.HandleSslSetFd, &link.UprobeOptions{PID: int(pid), Address: offset})
	if err != nil {
		return nil, fmt.Errorf("attach uprobe SSL_set_fd: %w", err)
	}
	return &SSLLinks{links: []link.Link{lnk}}, nil
}

// AttachSSLReadWrite attaches the SSL_write/SSL_read/SSL_free uprobes (and
// the optional _ex variants, when present) for pid against the shared obj's
// programs.
func AttachSSLReadWrite(obj *SSLObjects, pid uint32, libsslPath string) (*SSLLinks, error) {
	if err := checkLibSSLExecutable(libsslPath); err != nil {
		return nil, err
	}
	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		return nil, fmt.Errorf("open executable %s: %w", libsslPath, err)
	}

	opts := func(offset uint64) *link.UprobeOptions {
		return &link.UprobeOptions{PID: int(pid), Address: offset}
	}
	hooks := []struct {
		symbol   string
		ret      bool
		required bool
		prog     *ebpf.Program
	}{
		{"SSL_write", false, true, obj.objs.HandleSslWrite},
		{"SSL_read", false, true, obj.objs.HandleSslRead},
		{"SSL_read", true, true, obj.objs.HandleSslReadRet},
		{"SSL_write_ex", false, false, obj.objs.HandleSslWriteEx},
		{"SSL_read_ex", false, false, obj.objs.HandleSslReadEx},
		{"SSL_read_ex", true, false, obj.objs.HandleSslReadExRet},
		{"SSL_free", false, true, obj.objs.HandleSslFree},
	}

	links := &SSLLinks{}
	for _, h := range hooks {
		offset, ok := obj.offsets[h.symbol]
		if !ok {
			if h.required {
				_ = links.Close()
				return nil, fmt.Errorf("attach uprobe %s: %w", h.symbol, link.ErrNoSymbol)
			}
			continue
		}
		attach := ex.Uprobe
		if h.ret {
			attach = ex.Uretprobe
		}
		lnk, err := attach(h.symbol, h.prog, opts(offset))
		if err != nil {
			if !h.required && errors.Is(err, link.ErrNoSymbol) {
				continue
			}
			_ = links.Close()
			return nil, fmt.Errorf("attach uprobe %s: %w", h.symbol, err)
		}
		links.links = append(links.links, lnk)
	}

	return links, nil
}
