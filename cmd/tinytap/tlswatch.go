package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shinagawa-web/tinytap/internal/drops"
	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
	"github.com/shinagawa-web/tinytap/internal/tls"
)

type dropCounter interface {
	DropCounts() drops.Counts
}

// sslRegistryCloser is the one method sslWatcher needs from
// *loader.SSLRegistry — a narrow seam so tests can inject a registry whose
// Close fails, without needing real eBPF privileges to construct one.
type sslRegistryCloser interface {
	Close() error
}

// sslRegistryShared is (*loader.SSLRegistry).Shared, indirected through a
// package-level var so tests can simulate a successful load — which
// otherwise needs real eBPF privileges — the same way attachSSLReadWrite
// used to for the pre-#327 per-pid probes.
var sslRegistryShared = (*loader.SSLRegistry).Shared

// sslObjects is the subset of *loader.SSLObjects the watcher needs. One
// sslObjects is shared by every pid that maps the same libssl inode (#327);
// AttachSetFd/AttachPayload create the per-pid uprobe links against it.
type sslObjects interface {
	Lookup(pid uint32, ssl uint64) (int32, bool)
	Delete(pid uint32, ssl uint64)
	DeletePids(dead map[uint32]bool) int
	DropCounts() drops.Counts
	AttachSetFd(pid uint32, libsslPath string) (io.Closer, error)
	AttachPayload(pid uint32, libsslPath string) (io.Closer, error)
	reader() ringbufReader
}

// sslObjectsAdapter bridges *loader.SSLObjects (a struct with a Reader
// field) to the sslObjects interface, and delegates attachment to the
// loader's package-level AttachSSLSetFd/AttachSSLReadWrite.
type sslObjectsAdapter struct{ *loader.SSLObjects }

func (a sslObjectsAdapter) reader() ringbufReader { return a.Reader }

func (a sslObjectsAdapter) AttachSetFd(pid uint32, libsslPath string) (io.Closer, error) {
	return loader.AttachSSLSetFd(a.SSLObjects, pid, libsslPath)
}

func (a sslObjectsAdapter) AttachPayload(pid uint32, libsslPath string) (io.Closer, error) {
	return loader.AttachSSLReadWrite(a.SSLObjects, pid, libsslPath)
}

// pidAttachment is one pid's uprobe links against a shared sslObjects.
// payload is nil when the payload attach failed — the SSL_set_fd link is
// kept for fd correlation regardless (#147).
type pidAttachment struct {
	obj     sslObjects
	fdLinks io.Closer
	payload io.Closer
}

type sslWatcher struct {
	output.Sink

	sinkMu sync.Mutex

	mu          sync.Mutex
	closed      bool
	seen        map[uint32]bool
	attached    map[uint32]*pidAttachment
	caps        map[sslObjects]*tlsStreams // one entry per libssl inode, added when shared() reports created
	closedDrops drops.Counts

	reg sslRegistryCloser

	find   func(pid uint32) (tls.Discovery, error)
	shared func(libsslPath string) (sslObjects, bool, error)

	// isAlive reports whether the process with the given pid is still running.
	// Replaced by tests to avoid /proc dependency.
	isAlive func(pid uint32) bool

	// attachSem caps the number of goroutines concurrently inside the BPF
	// load+attach section to bound the number of in-flight kernel BPF fds
	// under high-churn TLS workloads (#326). Since BPF objects are now loaded
	// once per libssl inode rather than once per pid (#327), the section this
	// guards is a one-time per-inode load plus a handful of Uprobe calls, not
	// a full load on every attach.
	attachSem     chan struct{}
	attachSkipped atomic.Uint64

	findRetries    int
	findRetryDelay time.Duration

	stopReaper    chan struct{}
	reaperStopped chan struct{}

	closeOnce sync.Once
	closeErr  error
}

const (
	defaultFindRetries    = 8
	defaultFindRetryDelay = 25 * time.Millisecond

	// maxConcurrentAttach caps goroutines inside the BPF load+attach critical
	// section simultaneously. By Little's Law (N = λ × W), cap/W gives the
	// maximum attach rate without throttling: 512 / 0.42 s ≈ 1200 attaches/s,
	// which covers workloads well above the 700 req/s design target (#326).
	maxConcurrentAttach = 512

	// seenSweepBudget bounds how many `seen` entries the reaper stats per
	// tick when reclaiming pids that never got an attachment (find failure,
	// missing symbols, attach failure — all of which deliberately keep
	// seen[pid]=true to suppress retry storms against processes with no or
	// broken libssl). Go randomizes map iteration order, so a bounded check
	// per tick still converges over time without ever touching every entry
	// at once.
	seenSweepBudget = 256
)

var reaperInterval = time.Second

// procFSAvailable is false on non-Linux systems where /proc does not exist.
var procFSAvailable = func() bool {
	_, err := os.Stat("/proc")
	return err == nil
}()

// statProcEntry is os.Stat, overridden by tests to inject stat errors other
// than os.ErrNotExist without depending on real /proc permissions.
var statProcEntry = os.Stat

// defaultIsAlive checks whether pid still has a /proc entry. On non-Linux
// systems (e.g. macOS for development), it always returns true to avoid
// spuriously skipping attachment in tests. Only a missing /proc/<pid> entry
// counts as dead; any other stat error (e.g. permission denied under
// /proc hidepid) is treated as alive, since we can't actually tell.
func defaultIsAlive(pid uint32) bool {
	if !procFSAvailable {
		return true
	}
	_, err := statProcEntry(fmt.Sprintf("/proc/%d", pid))
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}

func newSSLWatcher(sink output.Sink) *sslWatcher {
	reg := loader.NewSSLRegistry()
	w := &sslWatcher{
		Sink:     sink,
		seen:     make(map[uint32]bool),
		attached: make(map[uint32]*pidAttachment),
		caps:     make(map[sslObjects]*tlsStreams),
		reg:      reg,
		find:     func(pid uint32) (tls.Discovery, error) { return tls.Find("", pid) },
		shared: func(libsslPath string) (sslObjects, bool, error) {
			obj, created, err := sslRegistryShared(reg, libsslPath)
			if err != nil {
				return nil, false, err
			}
			return sslObjectsAdapter{obj}, created, nil
		},
		findRetries:    defaultFindRetries,
		findRetryDelay: defaultFindRetryDelay,
		isAlive:        defaultIsAlive,
		attachSem:      make(chan struct{}, maxConcurrentAttach),
		stopReaper:     make(chan struct{}),
		reaperStopped:  make(chan struct{}),
	}
	go w.runReaper()
	return w
}

func (w *sslWatcher) OnEvent(e *events.Event) {
	w.sinkMu.Lock()
	w.Sink.OnEvent(e)
	w.sinkMu.Unlock()
	w.maybeAttach(e.Pid)
}

func (w *sslWatcher) OnMessage(m http.Message) {
	w.sinkMu.Lock()
	defer w.sinkMu.Unlock()
	w.Sink.OnMessage(m)
}

func (w *sslWatcher) OnPaired(pe http.PairedEvent) {
	w.sinkMu.Lock()
	defer w.sinkMu.Unlock()
	w.Sink.OnPaired(pe)
}

func (w *sslWatcher) Run() error {
	if r, ok := w.Sink.(interface{ Run() error }); ok {
		return r.Run()
	}
	return nil
}

func (w *sslWatcher) Quit() {
	if r, ok := w.Sink.(interface{ Quit() }); ok {
		r.Quit()
	}
}

func (w *sslWatcher) maybeAttach(pid uint32) {
	w.mu.Lock()
	if w.seen[pid] {
		w.mu.Unlock()
		return
	}
	w.seen[pid] = true
	w.mu.Unlock()

	go func() {
		disc, err := w.findWithRetry(pid)
		if err != nil {
			if errors.Is(err, tls.ErrLibSSLNotFound) {
				return
			}
			var symErr *tls.SymbolError
			if errors.As(err, &symErr) {
				log.Printf("tls: pid %d has libssl at %s but is missing required symbols %v — TLS capture unavailable for this process", pid, symErr.Path, symErr.Missing)
				return
			}
			log.Printf("tls: discover libssl for pid %d: %v", pid, err)
			return
		}

		// Skip BPF loading for processes that died after findWithRetry.
		if !w.isAlive(pid) {
			return
		}

		// Bound concurrent BPF loads to cap in-flight kernel fds (#326).
		// Non-blocking: if all slots are taken, clear seen[pid] so the next
		// event for this pid retries rather than being silently dropped.
		select {
		case w.attachSem <- struct{}{}:
		default:
			w.attachSkipped.Add(1)
			w.mu.Lock()
			delete(w.seen, pid)
			w.mu.Unlock()
			return
		}
		defer func() { <-w.attachSem }()

		obj, created, err := w.shared(disc.Path)
		if err != nil {
			log.Printf("tls: load SSL uprobe objects for pid %d (%s): %v", pid, disc.Path, err)
			return
		}

		if created {
			w.mu.Lock()
			if w.closed {
				w.mu.Unlock()
				return
			}
			st := newTLSStreams()
			w.caps[obj] = st
			w.mu.Unlock()
			go captureTLS(obj.reader(), obj, w, st)
			log.Printf("tls: SSL uprobe objects loaded for %s (shared by every process using it)", disc.Path)
		}

		fdLinks, err := obj.AttachSetFd(pid, disc.Path)
		if err != nil {
			log.Printf("tls: attach SSL_set_fd for pid %d (%s): %v", pid, disc.Path, err)
			return
		}

		att := &pidAttachment{obj: obj, fdLinks: fdLinks}
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			_ = fdLinks.Close()
			return
		}
		w.attached[pid] = att
		w.mu.Unlock()
		log.Printf("tls: SSL_set_fd uprobe attached for pid %d (%s)", pid, disc.Path)

		payload, err := obj.AttachPayload(pid, disc.Path)
		if err != nil {
			log.Printf("tls: attach SSL_write/SSL_read/SSL_free for pid %d (%s): %v", pid, disc.Path, err)
			return
		}

		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			_ = payload.Close()
			return
		}
		att.payload = payload
		w.mu.Unlock()
		log.Printf("tls: SSL_write/SSL_read/SSL_free uprobes attached for pid %d (%s)", pid, disc.Path)
	}()
}

func (w *sslWatcher) findWithRetry(pid uint32) (tls.Discovery, error) {
	for attempt := 0; ; attempt++ {
		disc, err := w.find(pid)
		if err == nil || !errors.Is(err, tls.ErrLibSSLNotFound) || attempt >= w.findRetries {
			return disc, err
		}
		// Don't retry for a process that has already exited — the library
		// will never appear and sleeping only wastes goroutine lifetime.
		if !w.isAlive(pid) {
			return tls.Discovery{}, tls.ErrLibSSLNotFound
		}
		time.Sleep(w.findRetryDelay)
	}
}

// harvestLocked folds a shared object's drop counters into closedDrops
// before the registry is closed — closing frees the underlying maps, so this
// is the last chance to read them. Caller must hold w.mu. Only called from
// close(): a shared object's drop_counters map outlives any individual pid,
// so harvesting it on pid reap would double-count the same drops on every
// later dropCounts() read.
func (w *sslWatcher) harvestLocked(p dropCounter) {
	w.closedDrops = w.closedDrops.Add(p.DropCounts())
}

// dropCounts totals drops across every live shared object plus those already
// harvested at Close. One drop_counters map is shared by every pid on the
// same libssl inode, so each live object is read exactly once here rather
// than once per pid.
func (w *sslWatcher) dropCounts() drops.Counts {
	w.mu.Lock()
	total := w.closedDrops
	for obj := range w.caps {
		total = total.Add(obj.DropCounts())
	}
	w.mu.Unlock()
	total.TLSAttachSkips = w.attachSkipped.Load()
	return total
}

func (w *sslWatcher) runReaper() {
	defer close(w.reaperStopped)
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.reapDeadProbes()
		case <-w.stopReaper:
			return
		}
	}
}

// reapDeadProbes closes uprobe links for processes that are no longer
// running, releasing the associated kernel fds and reclaiming their
// ssl_fd_map entries and parser state. The shared BPF objects themselves —
// and their drop counters and capture goroutine — outlive any individual pid
// and are only torn down by Close.
func (w *sslWatcher) reapDeadProbes() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}

	deadByObj := make(map[sslObjects]map[uint32]bool)
	var toClose []io.Closer
	type pidStream struct {
		pid uint32
		st  *tlsStreams
	}
	var toClosePid []pidStream

	for pid, att := range w.attached {
		if w.isAlive(pid) {
			continue
		}
		if att.payload != nil {
			toClose = append(toClose, att.payload)
		}
		if att.fdLinks != nil {
			toClose = append(toClose, att.fdLinks)
		}
		if deadByObj[att.obj] == nil {
			deadByObj[att.obj] = make(map[uint32]bool)
		}
		deadByObj[att.obj][pid] = true
		if st, ok := w.caps[att.obj]; ok {
			toClosePid = append(toClosePid, pidStream{pid, st})
		}
		delete(w.attached, pid)
		delete(w.seen, pid)
	}

	// Budgeted sweep of seen entries that never got an attachment — the
	// early-return paths in maybeAttach deliberately keep seen[pid]=true to
	// suppress retries, so only pids confirmed dead are reclaimed here.
	if n := len(w.seen); n > 0 {
		checked := 0
		for pid := range w.seen {
			if _, ok := w.attached[pid]; ok {
				continue
			}
			if !w.isAlive(pid) {
				delete(w.seen, pid)
			}
			checked++
			if checked >= seenSweepBudget && n > seenSweepBudget {
				break
			}
		}
	}

	w.mu.Unlock()

	for _, c := range toClose {
		if err := c.Close(); err != nil {
			log.Printf("tls: reaper: close probe for dead process: %v", err)
		}
	}
	for obj, dead := range deadByObj {
		obj.DeletePids(dead)
	}
	// closePid takes tlsStreams.mu, which the capture goroutine may hold
	// while calling back into w.mu via sink.OnEvent — call these only after
	// releasing w.mu above, or the two goroutines can deadlock on each
	// other's lock.
	for _, ps := range toClosePid {
		ps.st.closePid(ps.pid)
	}
}

// Close stops the reaper and closes all attachments, shared objects, and the
// sink. It is idempotent: calling it more than once, or concurrently,
// returns the result of the first call without re-closing stopReaper.
func (w *sslWatcher) Close() error {
	w.closeOnce.Do(func() {
		w.closeErr = w.close()
	})
	return w.closeErr
}

func (w *sslWatcher) close() error {
	close(w.stopReaper)
	<-w.reaperStopped

	w.mu.Lock()
	w.closed = true
	attached := w.attached
	w.attached = nil
	caps := w.caps
	w.caps = nil
	for obj := range caps {
		w.harvestLocked(obj)
	}
	w.mu.Unlock()

	var errs []error
	for pid, att := range attached {
		if att.payload != nil {
			if err := att.payload.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close SSL payload links for pid %d: %w", pid, err))
			}
		}
		if att.fdLinks != nil {
			if err := att.fdLinks.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close SSL_set_fd links for pid %d: %w", pid, err))
			}
		}
	}
	if err := w.reg.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close SSL uprobe objects: %w", err))
	}
	if err := w.Sink.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
