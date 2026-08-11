package main

import (
	"errors"
	"fmt"
	"log"
	"sync"
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

type sslProbe interface {
	Close() error
	Lookup(pid uint32, ssl uint64) (int32, bool)
	Delete(pid uint32, ssl uint64)
	DropCounts() drops.Counts
}

type payloadProbe interface {
	Close() error
	reader() ringbufReader
	DropCounts() drops.Counts
}

type payloadProbeAdapter struct {
	*loader.SSLPayloadProbe
}

func (a *payloadProbeAdapter) reader() ringbufReader { return a.Reader }

type sslWatcher struct {
	output.Sink

	sinkMu sync.Mutex

	mu            sync.Mutex
	closed        bool
	seen          map[uint32]bool
	probes        map[uint32]sslProbe
	payloadProbes map[uint32]payloadProbe
	closedDrops   drops.Counts

	find          func(pid uint32) (tls.Discovery, error)
	attach        func(pid uint32, path string) (sslProbe, error)
	attachPayload func(pid uint32, path string) (payloadProbe, error)

	findRetries    int
	findRetryDelay time.Duration
}

const (
	defaultFindRetries    = 8
	defaultFindRetryDelay = 25 * time.Millisecond
)

var attachSSLReadWrite = loader.AttachSSLReadWrite

func newSSLWatcher(sink output.Sink) *sslWatcher {
	return &sslWatcher{
		Sink:          sink,
		seen:          make(map[uint32]bool),
		probes:        make(map[uint32]sslProbe),
		payloadProbes: make(map[uint32]payloadProbe),
		find:          func(pid uint32) (tls.Discovery, error) { return tls.Find("", pid) },
		attach:        func(pid uint32, path string) (sslProbe, error) { return loader.AttachSSLSetFd(pid, path) },
		attachPayload: func(pid uint32, path string) (payloadProbe, error) {
			p, err := attachSSLReadWrite(pid, path)
			if err != nil {
				return nil, err
			}
			return &payloadProbeAdapter{p}, nil
		},
		findRetries:    defaultFindRetries,
		findRetryDelay: defaultFindRetryDelay,
	}
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

		probe, err := w.attach(pid, disc.Path)
		if err != nil {
			log.Printf("tls: attach SSL_set_fd for pid %d (%s): %v", pid, disc.Path, err)
			return
		}

		w.mu.Lock()
		if w.closed {
			w.harvestLocked(probe)
			w.mu.Unlock()
			_ = probe.Close()
			return
		}
		w.probes[pid] = probe
		w.mu.Unlock()
		log.Printf("tls: SSL_set_fd uprobe attached for pid %d (%s)", pid, disc.Path)

		pp, err := w.attachPayload(pid, disc.Path)
		if err != nil {
			log.Printf("tls: attach SSL_write/SSL_read/SSL_free for pid %d (%s): %v", pid, disc.Path, err)
			return
		}

		w.mu.Lock()
		if w.closed {
			w.harvestLocked(pp)
			w.mu.Unlock()
			_ = pp.Close()
			return
		}
		w.payloadProbes[pid] = pp
		w.mu.Unlock()
		log.Printf("tls: SSL_write/SSL_read/SSL_free uprobes attached for pid %d (%s)", pid, disc.Path)

		go captureTLS(pp.reader(), probe, w, http.NewParserWithResolve(resolveComm), http.NewPairer())
	}()
}

func (w *sslWatcher) findWithRetry(pid uint32) (tls.Discovery, error) {
	for attempt := 0; ; attempt++ {
		disc, err := w.find(pid)
		if err == nil || !errors.Is(err, tls.ErrLibSSLNotFound) || attempt >= w.findRetries {
			return disc, err
		}
		time.Sleep(w.findRetryDelay)
	}
}

// harvestLocked folds a probe's drop counters into closedDrops before the
// probe is closed — a closed probe's maps are gone, so this is the last
// chance to read them. Caller must hold w.mu.
func (w *sslWatcher) harvestLocked(p dropCounter) {
	w.closedDrops = w.closedDrops.Add(p.DropCounts())
}

// dropCounts totals drops across every live probe plus those already
// harvested from closed ones. Each attached pid loads its own copy of the
// uprobe object, so every probe carries its own drop_counters map and the
// per-probe reads must be summed here. Holds w.mu across a map lookup
// syscall per probe: call this at shutdown or on a coarse timer, never
// per event.
func (w *sslWatcher) dropCounts() drops.Counts {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := w.closedDrops
	for _, p := range w.probes {
		total = total.Add(p.DropCounts())
	}
	for _, p := range w.payloadProbes {
		total = total.Add(p.DropCounts())
	}
	return total
}

func (w *sslWatcher) Close() error {
	w.mu.Lock()
	w.closed = true
	probes := w.probes
	w.probes = nil
	payloadProbes := w.payloadProbes
	w.payloadProbes = nil
	for _, p := range probes {
		w.harvestLocked(p)
	}
	for _, p := range payloadProbes {
		w.harvestLocked(p)
	}
	w.mu.Unlock()

	var errs []error
	for pid, p := range probes {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close SSL_set_fd probe for pid %d: %w", pid, err))
		}
	}
	for pid, p := range payloadProbes {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close SSL payload probe for pid %d: %w", pid, err))
		}
	}
	if err := w.Sink.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
