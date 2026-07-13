package main

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/tls"
)

// sslWatcher wraps an output.Sink, forwarding every call unchanged, while
// watching for newly-observed pids and attaching a SSL_set_fd uprobe (#147)
// to any that have loaded libssl with the required symbols (per
// internal/tls.Find). Discovery+attach runs in a background goroutine, off
// the capture loop's mutex, so a slow /proc scan or ELF parse never delays
// event draining.
//
// Per-pid dedup only — tinytap has no process-exit tracepoint today, so
// attached probes accumulate for the process's lifetime and are all closed
// together on tinytap shutdown via Close(). Acceptable for a dev-environment
// tool watching a handful of long-lived processes (nginx, curl invocations).
// sslProbe is the subset of *loader.SSLFdProbe that sslWatcher needs —
// narrowed to an interface so tests can inject a fake instead of a real
// eBPF-backed probe.
type sslProbe interface {
	Close() error
}

type sslWatcher struct {
	output.Sink

	mu     sync.Mutex
	seen   map[uint32]bool
	probes map[uint32]sslProbe

	find   func(pid uint32) (tls.Discovery, error)
	attach func(pid uint32, path string) (sslProbe, error)
}

func newSSLWatcher(sink output.Sink) *sslWatcher {
	return &sslWatcher{
		Sink:   sink,
		seen:   make(map[uint32]bool),
		probes: make(map[uint32]sslProbe),
		find:   func(pid uint32) (tls.Discovery, error) { return tls.Find("", pid) },
		attach: func(pid uint32, path string) (sslProbe, error) { return loader.AttachSSLSetFd(pid, path) },
	}
}

func (w *sslWatcher) OnEvent(e *events.Event) {
	w.Sink.OnEvent(e)
	w.maybeAttach(e.Pid)
}

// Run and Quit forward to the wrapped sink when it's a tuiRunner (the TUI
// case — see runTUI in run.go, which passes the same wrapped sink as both
// the output.Sink and the tuiRunner). They're no-ops when it isn't (the
// stdout case), so sslWatcher satisfies tuiRunner either way.
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

// maybeAttach dedupes on pid, then discovers+attaches off the caller's
// goroutine so a slow /proc scan or ELF parse never blocks the capture
// loop. ErrLibSSLNotFound (no TLS, or a statically-linked stack) is the
// overwhelmingly common case and stays silent; a *tls.SymbolError
// (stripped/nonstandard libssl) logs once, matching #144's "fail fast and
// say so" policy for stripped binaries. A successful attach logs
// confirmation.
func (w *sslWatcher) maybeAttach(pid uint32) {
	w.mu.Lock()
	if w.seen[pid] {
		w.mu.Unlock()
		return
	}
	w.seen[pid] = true
	w.mu.Unlock()

	go func() {
		disc, err := w.find(pid)
		if err != nil {
			var symErr *tls.SymbolError
			if errors.As(err, &symErr) {
				log.Printf("tls: pid %d has libssl at %s but is missing required symbols %v — TLS capture unavailable for this process", pid, symErr.Path, symErr.Missing)
			}
			return
		}

		probe, err := w.attach(pid, disc.Path)
		if err != nil {
			log.Printf("tls: attach SSL_set_fd for pid %d (%s): %v", pid, disc.Path, err)
			return
		}

		w.mu.Lock()
		w.probes[pid] = probe
		w.mu.Unlock()
		log.Printf("tls: SSL_set_fd uprobe attached for pid %d (%s)", pid, disc.Path)
	}()
}

// Close closes every attached probe (joining errors), then the wrapped sink.
func (w *sslWatcher) Close() error {
	w.mu.Lock()
	probes := w.probes
	w.probes = nil
	w.mu.Unlock()

	var errs []error
	for pid, p := range probes {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close SSL_set_fd probe for pid %d: %w", pid, err))
		}
	}
	if err := w.Sink.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
