package main

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
	"github.com/shinagawa-web/tinytap/internal/tls"
)

// sslWatcher wraps an output.Sink, forwarding every call unchanged, while
// watching for newly-observed pids and attaching the SSL_set_fd uprobe
// (#147) and the SSL_write/SSL_read/SSL_free uprobes (#146/#173) to any that
// have loaded libssl with the required symbols (per internal/tls.Find).
// Discovery+attach runs in a background goroutine, off the capture loop's
// mutex, so a slow /proc scan or ELF parse never delays event draining.
//
// A successful attach spawns a captureTLS goroutine draining that pid's
// payload ringbuf into its own dedicated Parser/Pairer, rendering through
// this same sslWatcher (see sinkMu) — never through capture's own
// plaintext Parser/Pairer, and never calling the wrapped sink directly
// without sinkMu held, since capture's own loop, every captureTLS goroutine,
// and each one's periodic sweeper all call into the same underlying sink
// concurrently. Sink implementations assume a single caller (e.g.
// http.TimeAnchor.WallTime mutates unguarded state on first call), so
// sinkMu is what makes that safe.
//
// Per-pid dedup only — tinytap has no process-exit tracepoint today, so
// attached probes accumulate for the process's lifetime and are all closed
// together on tinytap shutdown via Close(). Acceptable for a dev-environment
// tool watching a handful of long-lived processes (nginx, curl invocations).
//
// Known gap: curl never calls SSL_set_fd — it wires OpenSSL to the socket via
// a custom BIO_METHOD instead, consistently across current stable versions
// (see lib/vtls/openssl.c in curl/curl). This probe will attach to curl
// processes but the SSL_set_fd uprobe never fires, so curl's SSL_write/
// SSL_read payloads are captured but dropped by captureTLS today — full HTTP
// parsing for fd-less connections needs a parser-level SSL*-keyed stream
// that doesn't exist yet (flagged on #149 against #171's premise).

// sslProbe is the subset of *loader.SSLFdProbe sslWatcher needs — narrowed
// to an interface so tests can inject a fake instead of a real eBPF-backed
// probe. Lookup makes any sslProbe usable directly as captureTLS's
// sslFdLookup, with no adapter needed.
type sslProbe interface {
	Close() error
	Lookup(pid uint32, ssl uint64) (int32, bool)
}

// payloadProbe is the subset of *loader.SSLPayloadProbe sslWatcher needs —
// narrowed to an interface, like sslProbe, so tests can inject a fake.
// reader (unexported, mirroring bpfSession's own reader() method in bpf.go)
// abstracts the concrete *loader.SSLPayloadProbe.Reader field behind a
// method, since Go interfaces can't require a struct field directly.
type payloadProbe interface {
	Close() error
	reader() ringbufReader
}

// payloadProbeAdapter implements payloadProbe by delegating to a real
// *loader.SSLPayloadProbe, so the struct itself carries no eBPF dependency
// beyond this one field and can be swapped for a fake in tests.
type payloadProbeAdapter struct {
	*loader.SSLPayloadProbe
}

func (a *payloadProbeAdapter) reader() ringbufReader { return a.Reader }

type sslWatcher struct {
	output.Sink

	sinkMu sync.Mutex // guards every call into the embedded Sink (see doc comment above)

	mu            sync.Mutex
	closed        bool
	seen          map[uint32]bool
	probes        map[uint32]sslProbe
	payloadProbes map[uint32]payloadProbe

	find          func(pid uint32) (tls.Discovery, error)
	attach        func(pid uint32, path string) (sslProbe, error)
	attachPayload func(pid uint32, path string) (payloadProbe, error)
}

// attachSSLReadWrite is the real loader.AttachSSLReadWrite; tests can
// replace it with a fake that succeeds without touching real eBPF (mirrors
// bpf.go's loaderLoad var for the same reason: the success path of an
// eBPF-backed attach can't be exercised by a plain unit test otherwise).
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
// say so" policy for stripped binaries; any other find error (e.g. a
// permission-denied /proc read) is unexpected and logged so discovery
// failures aren't silently invisible in real deployments. A successful
// attach logs confirmation.
//
// The SSL_set_fd probe and the payload (SSL_write/SSL_read/SSL_free) probe
// are attached independently: a payload-attach failure is logged and
// skipped rather than tearing down the fd probe, since fd correlation alone
// is still useful (#147) even without plaintext capture.
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
			w.mu.Unlock()
			// The watcher shut down while discovery+attach was in flight —
			// don't write to (and don't leak) a probe nobody will close.
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

// Close closes every attached probe (joining errors), then the wrapped sink.
// Marks the watcher closed first so any maybeAttach goroutine still in
// flight closes its own probe instead of racing a write into probes after
// it's been handed off here (see maybeAttach's closed check). Closing a
// payloadProbe closes its ringbuf reader too, which is what makes the
// corresponding captureTLS goroutine's blocking Read() return and exit.
func (w *sslWatcher) Close() error {
	w.mu.Lock()
	w.closed = true
	probes := w.probes
	w.probes = nil
	payloadProbes := w.payloadProbes
	w.payloadProbes = nil
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
