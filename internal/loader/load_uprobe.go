//go:build amd64 || arm64

package loader

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/drops"
	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

var ErrLibSSLNotExecutable = errors.New("libssl path has no execute permission bit set (try: sudo chmod +x <path>)")

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

type SSLFdProbe struct {
	objs bpf.TinytapUprobeObjects
	link link.Link
}

func AttachSSLSetFd(pid uint32, libsslPath string) (*SSLFdProbe, error) {
	if err := checkLibSSLExecutable(libsslPath); err != nil {
		return nil, err
	}

	spec, err := bpf.LoadTinytapUprobe()
	if err != nil {
		return nil, fmt.Errorf("load uprobe spec: %w", err)
	}

	p := &SSLFdProbe{}
	if err := spec.LoadAndAssign(&p.objs, nil); err != nil {
		return nil, fmt.Errorf("load uprobe objects: %w", err)
	}

	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		_ = p.objs.Close()
		return nil, fmt.Errorf("open executable %s: %w", libsslPath, err)
	}

	lnk, err := ex.Uprobe("SSL_set_fd", p.objs.HandleSslSetFd, &link.UprobeOptions{PID: int(pid)})
	if err != nil {
		_ = p.objs.Close()
		return nil, fmt.Errorf("attach uprobe SSL_set_fd: %w", err)
	}
	p.link = lnk

	return p, nil
}

func (p *SSLFdProbe) Lookup(pid uint32, ssl uint64) (int32, bool) {
	key := bpf.TinytapUprobeSslFdKey{Pid: pid, Ssl: ssl}
	var fd int32
	if err := p.objs.SslFdMap.Lookup(&key, &fd); err != nil {
		return 0, false
	}
	return fd, true
}

func (p *SSLFdProbe) DropCounts() drops.Counts {
	if p.objs.DropCounters == nil {
		return drops.Counts{}
	}
	return readDrops(p.objs.DropCounters)
}

func (p *SSLFdProbe) Close() error {
	var errs []error
	if p.link != nil {
		if err := p.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close uprobe link: %w", err))
		}
	}
	if err := p.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close uprobe objects: %w", err))
	}
	return errors.Join(errs...)
}

type SSLPayloadProbe struct {
	objs   bpf.TinytapUprobeObjects
	links  []link.Link
	Reader *ringbuf.Reader
}

func AttachSSLReadWrite(pid uint32, libsslPath string) (*SSLPayloadProbe, error) {
	if err := checkLibSSLExecutable(libsslPath); err != nil {
		return nil, err
	}

	spec, err := bpf.LoadTinytapUprobe()
	if err != nil {
		return nil, fmt.Errorf("load uprobe spec: %w", err)
	}

	p := &SSLPayloadProbe{}
	if err := spec.LoadAndAssign(&p.objs, nil); err != nil {
		return nil, fmt.Errorf("load uprobe objects: %w", err)
	}

	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		_ = p.objs.Close()
		return nil, fmt.Errorf("open executable %s: %w", libsslPath, err)
	}

	opts := &link.UprobeOptions{PID: int(pid)}
	hooks := []struct {
		symbol   string
		ret      bool
		required bool
		prog     *ebpf.Program
	}{
		{"SSL_write", false, true, p.objs.HandleSslWrite},
		{"SSL_read", false, true, p.objs.HandleSslRead},
		{"SSL_read", true, true, p.objs.HandleSslReadRet},
		{"SSL_write_ex", false, false, p.objs.HandleSslWriteEx},
		{"SSL_read_ex", false, false, p.objs.HandleSslReadEx},
		{"SSL_read_ex", true, false, p.objs.HandleSslReadExRet},
		{"SSL_free", false, true, p.objs.HandleSslFree},
	}
	for _, h := range hooks {
		attach := ex.Uprobe
		if h.ret {
			attach = ex.Uretprobe
		}
		lnk, err := attach(h.symbol, h.prog, opts)
		if err != nil {
			if !h.required && errors.Is(err, link.ErrNoSymbol) {
				continue
			}
			_ = p.Close()
			return nil, fmt.Errorf("attach uprobe %s: %w", h.symbol, err)
		}
		p.links = append(p.links, lnk)
	}

	rd, err := ringbuf.NewReader(p.objs.SslEvents)
	if err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("open ssl ringbuf: %w", err)
	}
	p.Reader = rd

	return p, nil
}

func (p *SSLPayloadProbe) DropCounts() drops.Counts {
	if p.objs.DropCounters == nil {
		return drops.Counts{}
	}
	return readDrops(p.objs.DropCounters)
}

func (p *SSLPayloadProbe) Close() error {
	var errs []error
	if p.Reader != nil {
		if err := p.Reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close ssl ringbuf: %w", err))
		}
	}
	for _, lnk := range p.links {
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close uprobe link: %w", err))
		}
	}
	if err := p.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close uprobe objects: %w", err))
	}
	return errors.Join(errs...)
}
