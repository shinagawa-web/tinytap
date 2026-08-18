package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shinagawa-web/tinytap/internal/drops"
	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
	"github.com/shinagawa-web/tinytap/internal/tls"
)

// syncBuffer is a concurrency-safe io.Writer that signals done the first
// time it's written to — used to synchronize with log output produced by
// sslWatcher's background discovery goroutine without a data race on the
// underlying buffer.
type syncBuffer struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	done chan struct{}
	once sync.Once
}

func newSyncBuffer() *syncBuffer {
	return &syncBuffer{done: make(chan struct{})}
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.buf.Write(p)
	s.mu.Unlock()
	s.once.Do(func() { close(s.done) })
	return n, err
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// fakeProbe's closed field uses atomic.Bool since
// TestSSLWatcher_OnEvent_ClosedDuringAttach reads it from a polling loop
// concurrently with Close() writing it from sslWatcher's background
// goroutine — a plain bool would race under -race.
type fakeProbe struct {
	closeErr   error
	closed     atomic.Bool
	lookupFd   int32
	lookupOK   bool
	dropCounts drops.Counts
}

func (f *fakeProbe) Lookup(uint32, uint64) (int32, bool) { return f.lookupFd, f.lookupOK }

func (f *fakeProbe) Delete(uint32, uint64) {}

func (f *fakeProbe) DropCounts() drops.Counts { return f.dropCounts }

func (f *fakeProbe) Close() error {
	f.closed.Store(true)
	return f.closeErr
}

// waitOnChan blocks until ch receives or fails the test after timeout —
// used to synchronize with sslWatcher's background discovery goroutine.
func waitOnChan(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for background discovery goroutine")
	}
}

// TestNewSSLWatcher_DefaultFindAndAttach exercises the real (non-injected)
// find/attach/attachPayload closures newSSLWatcher wires up by default —
// every other test in this file overrides w.find/w.attach/w.attachPayload
// before use. All three real functions fail fast without root: tls.Find on
// a pid unlikely to have libssl mapped, and loader.AttachSSLSetFd /
// loader.AttachSSLReadWrite on a nonexistent path (which fail at the
// os.Stat check before touching eBPF).
func TestNewSSLWatcher_DefaultFindAndAttach(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})

	if _, err := w.find(uint32(os.Getpid())); err == nil {
		t.Error("find(own pid) = nil error, want an error (no libssl expected in this test binary)")
	}
	if _, err := w.attach(1, "/nonexistent-path-xyz"); err == nil {
		t.Error("attach(nonexistent path) = nil error, want an error")
	}
	if _, err := w.attachPayload(1, "/nonexistent-path-xyz"); err == nil {
		t.Error("attachPayload(nonexistent path) = nil error, want an error")
	}
}

// TestFindWithRetry_SucceedsAfterTransientNotFound is the concrete
// verification for the race findWithRetry exists to ride out (measured on
// this dev VM: curl's libssl.so isn't mapped into /proc/<pid>/maps for the
// first ~11ms after exec — see findWithRetry's doc comment): a discovery
// that fails with ErrLibSSLNotFound on its first attempts but succeeds
// before the retry budget is exhausted must still return the discovery.
func TestFindWithRetry_SucceedsAfterTransientNotFound(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	w.findRetries = 3
	w.findRetryDelay = time.Millisecond
	var calls int
	want := tls.Discovery{Pid: 1, Path: "/lib/libssl.so.3"}
	w.find = func(pid uint32) (tls.Discovery, error) {
		calls++
		if calls < 3 {
			return tls.Discovery{}, tls.ErrLibSSLNotFound
		}
		return want, nil
	}

	got, err := w.findWithRetry(1)
	if err != nil {
		t.Fatalf("findWithRetry() error = %v, want nil", err)
	}
	if got != want {
		t.Errorf("findWithRetry() = %+v, want %+v", got, want)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3 (2 transient failures + 1 success)", calls)
	}
}

// TestFindWithRetry_GivesUpAfterExhaustingRetries confirms a process that
// genuinely never loads libssl (the overwhelmingly common case — most
// processes never touch TLS) is still correctly given up on once the retry
// budget elapses, rather than retrying forever.
func TestFindWithRetry_GivesUpAfterExhaustingRetries(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	w.findRetries = 2
	w.findRetryDelay = time.Millisecond
	var calls int
	w.find = func(pid uint32) (tls.Discovery, error) {
		calls++
		return tls.Discovery{}, tls.ErrLibSSLNotFound
	}

	_, err := w.findWithRetry(1)
	if !errors.Is(err, tls.ErrLibSSLNotFound) {
		t.Errorf("findWithRetry() error = %v, want ErrLibSSLNotFound", err)
	}
	if calls != 3 { // 1 initial attempt + findRetries(2) retries
		t.Errorf("calls = %d, want 3 (1 initial + 2 retries)", calls)
	}
}

// TestFindWithRetry_NonNotFoundErrorDoesNotRetry confirms only
// ErrLibSSLNotFound triggers a retry — a *tls.SymbolError or an unexpected
// error (e.g. permission denied) returns immediately, matching
// TestSSLWatcher_OnEvent_SymbolError/UnexpectedFindError's existing
// single-call expectations.
func TestFindWithRetry_NonNotFoundErrorDoesNotRetry(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	w.findRetries = 5
	w.findRetryDelay = time.Millisecond
	var calls int
	wantErr := errors.New("permission denied")
	w.find = func(pid uint32) (tls.Discovery, error) {
		calls++
		return tls.Discovery{}, wantErr
	}

	_, err := w.findWithRetry(1)
	if !errors.Is(err, wantErr) {
		t.Errorf("findWithRetry() error = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no retry for a non-ErrLibSSLNotFound error)", calls)
	}
}

func TestSSLWatcher_OnEvent_Dedup(t *testing.T) {
	calls := make(chan struct{}, 10)
	var findCount int
	w := newSSLWatcher(&fakeSink{})
	w.findRetries = 0 // isolate dedup-on-pid from findWithRetry's own retry loop
	w.find = func(pid uint32) (tls.Discovery, error) {
		findCount++
		calls <- struct{}{}
		return tls.Discovery{}, tls.ErrLibSSLNotFound
	}

	w.OnEvent(&events.Event{Pid: 42})
	waitOnChan(t, calls)
	w.OnEvent(&events.Event{Pid: 42})
	w.OnEvent(&events.Event{Pid: 42})

	// No second/third find call should ever land — give any errant goroutine
	// a moment to (wrongly) fire before asserting the count stayed at 1.
	time.Sleep(50 * time.Millisecond)
	if findCount != 1 {
		t.Errorf("findCount = %d, want 1 (dedup on pid)", findCount)
	}
}

func TestSSLWatcher_OnEvent_LibSSLNotFound(t *testing.T) {
	calls := make(chan struct{}, 1)
	w := newSSLWatcher(&fakeSink{})
	w.findRetries = 0 // isolate this from findWithRetry's own retry loop (tested separately)
	w.find = func(pid uint32) (tls.Discovery, error) {
		defer close(calls)
		return tls.Discovery{}, tls.ErrLibSSLNotFound
	}
	w.attach = func(pid uint32, path string) (sslProbe, error) {
		t.Fatal("attach should not be called when find fails")
		return nil, nil
	}

	w.OnEvent(&events.Event{Pid: 7})
	waitOnChan(t, calls)

	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.probes) != 0 {
		t.Errorf("probes = %v, want empty", w.probes)
	}
}

func TestSSLWatcher_OnEvent_UnexpectedFindError(t *testing.T) {
	logBuf := newSyncBuffer()
	orig := log.Writer()
	log.SetOutput(logBuf)
	defer log.SetOutput(orig)

	w := newSSLWatcher(&fakeSink{})
	findErr := errors.New("permission denied")
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{}, findErr
	}

	w.OnEvent(&events.Event{Pid: 21})
	waitOnChan(t, logBuf.done)

	if !strings.Contains(logBuf.String(), "permission denied") {
		t.Errorf("log output = %q, want mention of the unexpected error", logBuf.String())
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.probes) != 0 {
		t.Errorf("probes = %v, want empty", w.probes)
	}
}

func TestSSLWatcher_OnEvent_ClosedDuringAttach(t *testing.T) {
	attaching := make(chan struct{})
	release := make(chan struct{})
	fp := &fakeProbe{dropCounts: drops.Counts{Ringbuf: 3, MapFull: 5}}
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.attach = func(pid uint32, path string) (sslProbe, error) {
		close(attaching)
		<-release
		return fp, nil
	}

	w.OnEvent(&events.Event{Pid: 23})
	<-attaching // attach is in flight; Close() races it below

	if err := w.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	close(release) // let the in-flight attach complete after Close() returned

	deadline := time.Now().Add(2 * time.Second)
	for !fp.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !fp.closed.Load() {
		t.Error("probe attached after Close() was never closed (leaked)")
	}
	if got, want := w.dropCounts(), (drops.Counts{Ringbuf: 3, MapFull: 5}); got != want {
		t.Errorf("dropCounts() = %+v, want %+v (racing probe's counts must be folded into closedDrops)", got, want)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.probes) != 0 {
		t.Errorf("probes = %v, want empty (closed watcher must not store new probes)", w.probes)
	}
}

func TestSSLWatcher_OnEvent_SymbolError(t *testing.T) {
	logBuf := newSyncBuffer()
	orig := log.Writer()
	log.SetOutput(logBuf)
	defer log.SetOutput(orig)

	w := newSSLWatcher(&fakeSink{})
	symErr := &tls.SymbolError{Path: "/lib/libssl.so.3", Missing: []string{"SSL_set_fd"}}
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{}, symErr
	}

	w.OnEvent(&events.Event{Pid: 9})
	waitOnChan(t, logBuf.done)

	if !strings.Contains(logBuf.String(), "missing required symbols") {
		t.Errorf("log output = %q, want mention of missing symbols", logBuf.String())
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.probes) != 0 {
		t.Errorf("probes = %v, want empty", w.probes)
	}
}

// fakePayloadProbe implements payloadProbe. reader defaults to an empty
// fakeReader (returns EOF immediately, so any spawned captureTLS goroutine
// exits right away without needing explicit teardown in tests that don't
// care about its behavior).
type fakePayloadProbe struct {
	closeErr   error
	closed     atomic.Bool
	rd         ringbufReader
	dropCounts drops.Counts
}

func (f *fakePayloadProbe) DropCounts() drops.Counts { return f.dropCounts }

func (f *fakePayloadProbe) Close() error {
	f.closed.Store(true)
	return f.closeErr
}

func (f *fakePayloadProbe) reader() ringbufReader {
	if f.rd != nil {
		return f.rd
	}
	return &fakeReader{}
}

func TestSSLWatcher_OnEvent_Success(t *testing.T) {
	calls := make(chan struct{}, 1)
	payloadCalls := make(chan struct{}, 1)
	fp := &fakeProbe{}
	pp := &fakePayloadProbe{}
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.attach = func(pid uint32, path string) (sslProbe, error) {
		defer close(calls)
		if path != "/lib/libssl.so.3" {
			t.Errorf("attach path = %q, want /lib/libssl.so.3", path)
		}
		return fp, nil
	}
	w.attachPayload = func(pid uint32, path string) (payloadProbe, error) {
		defer close(payloadCalls)
		if path != "/lib/libssl.so.3" {
			t.Errorf("attachPayload path = %q, want /lib/libssl.so.3", path)
		}
		return pp, nil
	}

	w.OnEvent(&events.Event{Pid: 11})
	waitOnChan(t, calls)
	waitOnChan(t, payloadCalls)

	w.mu.Lock()
	stored, ok := w.probes[11]
	storedPayload, okPayload := w.payloadProbes[11]
	w.mu.Unlock()
	if !ok || stored != fp {
		t.Errorf("probes[11] = %v, %v; want %v, true", stored, ok, fp)
	}
	if !okPayload || storedPayload != pp {
		t.Errorf("payloadProbes[11] = %v, %v; want %v, true", storedPayload, okPayload, pp)
	}
}

func TestSSLWatcher_OnEvent_AttachError(t *testing.T) {
	calls := make(chan struct{}, 1)
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.attach = func(pid uint32, path string) (sslProbe, error) {
		defer close(calls)
		return nil, errors.New("attach fail")
	}
	w.attachPayload = func(pid uint32, path string) (payloadProbe, error) {
		t.Fatal("attachPayload should not be called when the fd attach fails")
		return nil, nil
	}

	w.OnEvent(&events.Event{Pid: 13})
	waitOnChan(t, calls)

	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.probes) != 0 {
		t.Errorf("probes = %v, want empty", w.probes)
	}
}

// TestSSLWatcher_OnEvent_PayloadAttachErrorKeepsFdProbe confirms a
// payload-attach failure is logged and skipped without rolling back the
// already-stored fd probe — fd correlation (#147) stays useful even when
// plaintext capture (#146) can't attach.
func TestSSLWatcher_OnEvent_PayloadAttachErrorKeepsFdProbe(t *testing.T) {
	calls := make(chan struct{}, 1)
	fp := &fakeProbe{}
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.attach = func(pid uint32, path string) (sslProbe, error) { return fp, nil }
	w.attachPayload = func(pid uint32, path string) (payloadProbe, error) {
		defer close(calls)
		return nil, errors.New("payload attach fail")
	}

	w.OnEvent(&events.Event{Pid: 17})
	waitOnChan(t, calls)

	w.mu.Lock()
	defer w.mu.Unlock()
	if stored, ok := w.probes[17]; !ok || stored != fp {
		t.Errorf("probes[17] = %v, %v; want %v, true (fd probe kept despite payload attach failure)", stored, ok, fp)
	}
	if len(w.payloadProbes) != 0 {
		t.Errorf("payloadProbes = %v, want empty", w.payloadProbes)
	}
}

func TestSSLWatcher_Close_JoinsProbeAndSinkErrors(t *testing.T) {
	sinkErr := errors.New("sink close fail")
	probeErr := errors.New("probe close fail")
	payloadProbeErr := errors.New("payload probe close fail")
	w := newSSLWatcher(&fakeSink{closeErr: sinkErr})
	fp1 := &fakeProbe{closeErr: probeErr}
	fp2 := &fakeProbe{}
	pp1 := &fakePayloadProbe{closeErr: payloadProbeErr}
	pp2 := &fakePayloadProbe{}
	w.probes[1] = fp1
	w.probes[2] = fp2
	w.payloadProbes[1] = pp1
	w.payloadProbes[2] = pp2

	err := w.Close()
	if err == nil {
		t.Fatal("Close() = nil, want error")
	}
	if !errors.Is(err, sinkErr) {
		t.Errorf("Close() error does not wrap sink close error: %v", err)
	}
	if !fp1.closed.Load() || !fp2.closed.Load() {
		t.Errorf("fp1.closed=%v fp2.closed=%v, want both true", fp1.closed.Load(), fp2.closed.Load())
	}
	if !pp1.closed.Load() || !pp2.closed.Load() {
		t.Errorf("pp1.closed=%v pp2.closed=%v, want both true", pp1.closed.Load(), pp2.closed.Load())
	}
}

func TestSSLWatcher_Close_NoProbes(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	if err := w.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

func TestSSLWatcher_DropCounts_Empty(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	if got := w.dropCounts(); got != (drops.Counts{}) {
		t.Errorf("dropCounts() = %+v, want zero value for a watcher with no probes", got)
	}
}

func TestSSLWatcher_DropCounts_SumsLiveProbes(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	w.probes[1] = &fakeProbe{dropCounts: drops.Counts{Ringbuf: 1, MapFull: 2}}
	w.probes[2] = &fakeProbe{dropCounts: drops.Counts{MapFull: 4}}
	w.payloadProbes[1] = &fakePayloadProbe{dropCounts: drops.Counts{Ringbuf: 8}}

	got := w.dropCounts()
	want := drops.Counts{Ringbuf: 9, MapFull: 6}
	if got != want {
		t.Errorf("dropCounts() = %+v, want %+v (sum across every live probe)", got, want)
	}
}

func TestSSLWatcher_DropCounts_RetainedAfterClose(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	w.probes[1] = &fakeProbe{dropCounts: drops.Counts{Ringbuf: 1, MapFull: 2}}
	w.probes[2] = &fakeProbe{dropCounts: drops.Counts{MapFull: 4}}
	w.payloadProbes[1] = &fakePayloadProbe{dropCounts: drops.Counts{Ringbuf: 8}}
	want := drops.Counts{Ringbuf: 9, MapFull: 6}

	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}

	if got := w.dropCounts(); got != want {
		t.Errorf("dropCounts() after Close() = %+v, want %+v (counts must survive probe teardown)", got, want)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.probes != nil || w.payloadProbes != nil {
		t.Errorf("probes=%v payloadProbes=%v, want both nil after Close()", w.probes, w.payloadProbes)
	}
}

// tuiFake implements both output.Sink (via embedding fakeSink) and the
// Run()/Quit() pair sslWatcher forwards to when present.
type tuiFake struct {
	fakeSink
	ran   bool
	quit  bool
	runFn func() error
}

func (f *tuiFake) Run() error {
	f.ran = true
	if f.runFn != nil {
		return f.runFn()
	}
	return nil
}

func (f *tuiFake) Quit() { f.quit = true }

func TestSSLWatcher_Run_Quit_Forwarded(t *testing.T) {
	inner := &tuiFake{}
	w := newSSLWatcher(inner)

	if err := w.Run(); err != nil {
		t.Errorf("Run() = %v, want nil", err)
	}
	w.Quit()

	if !inner.ran {
		t.Error("Run() was not forwarded to wrapped sink")
	}
	if !inner.quit {
		t.Error("Quit() was not forwarded to wrapped sink")
	}
}

func TestSSLWatcher_Run_Quit_NoOpWithoutTuiRunner(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})

	if err := w.Run(); err != nil {
		t.Errorf("Run() = %v, want nil no-op", err)
	}
	w.Quit() // must not panic
}

// TestSSLWatcher_OnMessage_Forwarded and TestSSLWatcher_OnPaired_Forwarded
// confirm the sinkMu-guarded overrides still forward to the wrapped sink —
// captureTLS calls these directly (sslWatcher itself is passed as its
// output.Sink), so they need the same forwarding behavior OnEvent already
// had before sinkMu was added.
func TestSSLWatcher_OnMessage_Forwarded(t *testing.T) {
	inner := &fakeSink{}
	w := newSSLWatcher(inner)
	w.OnMessage(http.Message{})
	if inner.messageCount != 1 {
		t.Errorf("messageCount = %d, want 1", inner.messageCount)
	}
}

func TestSSLWatcher_OnPaired_Forwarded(t *testing.T) {
	inner := &fakeSink{}
	w := newSSLWatcher(inner)
	w.OnPaired(http.PairedEvent{})
	if inner.pairedCount != 1 {
		t.Errorf("pairedCount = %d, want 1", inner.pairedCount)
	}
}

// TestNewSSLWatcher_DefaultAttachPayload_WrapsSuccess exercises the default
// attachPayload closure's success path — the one line that only runs when
// loader.AttachSSLReadWrite itself succeeds, which needs real eBPF and so
// can't be reached through the nonexistent-path failure case
// TestNewSSLWatcher_DefaultFindAndAttach already covers. attachSSLReadWrite
// is swapped for a fake that returns a real (never-attached) zero-value
// *loader.SSLPayloadProbe, proving the wrap into payloadProbeAdapter itself
// is correct without touching a kernel.
func TestNewSSLWatcher_DefaultAttachPayload_WrapsSuccess(t *testing.T) {
	orig := attachSSLReadWrite
	defer func() { attachSSLReadWrite = orig }()
	want := &loader.SSLPayloadProbe{}
	attachSSLReadWrite = func(pid uint32, path string) (*loader.SSLPayloadProbe, error) {
		return want, nil
	}

	w := newSSLWatcher(&fakeSink{})
	pp, err := w.attachPayload(1, "/lib/libssl.so.3")
	if err != nil {
		t.Fatalf("attachPayload() = %v, want nil error", err)
	}
	adapter, ok := pp.(*payloadProbeAdapter)
	if !ok || adapter.SSLPayloadProbe != want {
		t.Errorf("attachPayload() = %#v, want *payloadProbeAdapter wrapping %#v", pp, want)
	}
}

// TestPayloadProbeAdapter_Reader confirms the adapter delegates to the
// wrapped *loader.SSLPayloadProbe's Reader field — the one-line bridge that
// lets payloadProbe (a method-only interface) stand in for a struct field
// Go interfaces can't require directly (mirrors bpfSession's reader()
// pattern in bpf.go).
func TestPayloadProbeAdapter_Reader(t *testing.T) {
	inner := &loader.SSLPayloadProbe{}
	a := &payloadProbeAdapter{inner}
	if got := a.reader(); got != ringbufReader(inner.Reader) {
		t.Errorf("reader() = %v, want the wrapped probe's Reader field", got)
	}
}

// TestFindWithRetry_DeadProcessSkipsRetry confirms that when isAlive reports
// false, findWithRetry returns ErrLibSSLNotFound immediately without sleeping
// through the remaining retry budget. Without this, each goroutine spawned for
// a short-lived process wastes findRetries×findRetryDelay goroutine lifetime.
func TestFindWithRetry_DeadProcessSkipsRetry(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	w.findRetries = 5
	w.findRetryDelay = time.Millisecond
	w.isAlive = func(pid uint32) bool { return false } // process already gone

	var calls int
	w.find = func(pid uint32) (tls.Discovery, error) {
		calls++
		return tls.Discovery{}, tls.ErrLibSSLNotFound
	}

	_, err := w.findWithRetry(1)
	if !errors.Is(err, tls.ErrLibSSLNotFound) {
		t.Errorf("findWithRetry() error = %v, want ErrLibSSLNotFound", err)
	}
	// One initial find call, then isAlive returns false → immediate return.
	if calls != 1 {
		t.Errorf("find called %d times, want 1 (dead process must skip retries)", calls)
	}
}

// TestSSLWatcher_Reaper_ClosesProbesForDeadProcess verifies that
// reapDeadProbes removes and closes both the fd probe and the payload probe
// when the monitored process has exited.
func TestSSLWatcher_Reaper_ClosesProbesForDeadProcess(t *testing.T) {
	fp := &fakeProbe{dropCounts: drops.Counts{Ringbuf: 1}}
	pp := &fakePayloadProbe{dropCounts: drops.Counts{MapFull: 2}}
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	w.mu.Lock()
	w.probes[99] = fp
	w.payloadProbes[99] = pp
	w.seen[99] = true
	w.mu.Unlock()

	w.isAlive = func(pid uint32) bool { return pid != 99 }
	w.reapDeadProbes()

	if !fp.closed.Load() {
		t.Error("fd probe was not closed by reaper")
	}
	if !pp.closed.Load() {
		t.Error("payload probe was not closed by reaper")
	}

	w.mu.Lock()
	_, hasSeen := w.seen[99]
	_, hasProbe := w.probes[99]
	_, hasPayload := w.payloadProbes[99]
	harvested := w.closedDrops
	w.mu.Unlock()

	if hasSeen || hasProbe || hasPayload {
		t.Error("reaper did not remove dead pid from seen/probes/payloadProbes maps")
	}
	if want := (drops.Counts{Ringbuf: 1, MapFull: 2}); harvested != want {
		t.Errorf("closedDrops = %+v, want %+v (both probes must be harvested before close)", harvested, want)
	}
}

// TestSSLWatcher_Reaper_ClosesOnlyFdProbeForDeadProcess confirms that the
// reaper also closes fd-only probes (those where payload attachment failed,
// kept for fd correlation per #147) when the process exits.
func TestSSLWatcher_Reaper_ClosesOnlyFdProbeForDeadProcess(t *testing.T) {
	fp := &fakeProbe{}
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	w.mu.Lock()
	w.probes[88] = fp
	// No payloadProbes[88] — payload attach failed, fd probe kept for correlation.
	w.seen[88] = true
	w.mu.Unlock()

	w.isAlive = func(pid uint32) bool { return pid != 88 }
	w.reapDeadProbes()

	if !fp.closed.Load() {
		t.Error("fd-only probe was not closed by reaper")
	}
	w.mu.Lock()
	_, hasSeen := w.seen[88]
	_, hasProbe := w.probes[88]
	w.mu.Unlock()
	if hasSeen || hasProbe {
		t.Error("reaper did not remove dead pid from seen/probes maps")
	}
}

// TestSSLWatcher_MaybeAttach_SemaphoreSkipClearsSeenForRetry confirms that
// when the BPF-load semaphore is saturated the goroutine clears seen[pid] so
// a subsequent event for the same pid is not silently dropped.
func TestSSLWatcher_MaybeAttach_SemaphoreSkipClearsSeenForRetry(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	w.isAlive = func(pid uint32) bool { return true }

	// Fill every semaphore slot so the next goroutine takes the skip path.
	for range maxConcurrentAttach {
		w.attachSem <- struct{}{}
	}

	found := make(chan struct{}, 1)
	w.find = func(pid uint32) (tls.Discovery, error) {
		select {
		case found <- struct{}{}:
		default:
		}
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.attach = func(pid uint32, path string) (sslProbe, error) {
		t.Error("attach must not be called when semaphore is full")
		return nil, errors.New("unexpected")
	}

	w.OnEvent(&events.Event{Pid: 31})
	waitOnChan(t, found)         // goroutine reached find()
	time.Sleep(50 * time.Millisecond) // let it run to the semaphore branch and exit

	w.mu.Lock()
	_, stillSeen := w.seen[31]
	w.mu.Unlock()
	if stillSeen {
		t.Error("seen[pid] should be cleared after semaphore skip to allow retry on the next event")
	}
}

// TestSSLWatcher_MaybeAttach_SemaphoreSkipIncrementsCounter confirms that
// each semaphore-full skip increments attachSkipped, which flows into
// dropCounts() so the caller can report how many TLS processes were missed.
func TestSSLWatcher_MaybeAttach_SemaphoreSkipIncrementsCounter(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	w.isAlive = func(uint32) bool { return true }

	// Fill every semaphore slot so the next goroutine takes the skip path.
	for range maxConcurrentAttach {
		w.attachSem <- struct{}{}
	}

	found := make(chan struct{}, 1)
	w.find = func(pid uint32) (tls.Discovery, error) {
		select {
		case found <- struct{}{}:
		default:
		}
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}

	w.OnEvent(&events.Event{Pid: 32})
	waitOnChan(t, found)
	time.Sleep(50 * time.Millisecond) // let the goroutine reach and exit the skip branch

	if got := w.dropCounts().TLSAttachSkips; got != 1 {
		t.Errorf("dropCounts().TLSAttachSkips = %d, want 1", got)
	}
}

// TestSSLWatcher_OnEvent_ClosedDuringPayloadAttach mirrors
// TestSSLWatcher_OnEvent_ClosedDuringAttach but races Close() against the
// second (payload) attach stage instead of the first: the already-stored fd
// probe must survive, and the in-flight payload probe must be closed rather
// than stored or leaked.
func TestSSLWatcher_OnEvent_ClosedDuringPayloadAttach(t *testing.T) {
	attaching := make(chan struct{})
	release := make(chan struct{})
	fp := &fakeProbe{dropCounts: drops.Counts{Ringbuf: 1, MapFull: 2}}
	pp := &fakePayloadProbe{dropCounts: drops.Counts{Ringbuf: 4, MapFull: 8}}
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.attach = func(pid uint32, path string) (sslProbe, error) { return fp, nil }
	w.attachPayload = func(pid uint32, path string) (payloadProbe, error) {
		close(attaching)
		<-release
		return pp, nil
	}

	w.OnEvent(&events.Event{Pid: 29})
	<-attaching // payload attach is in flight; Close() races it below

	if err := w.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	close(release) // let the in-flight attach complete after Close() returned

	deadline := time.Now().Add(2 * time.Second)
	for !pp.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !pp.closed.Load() {
		t.Error("payload probe attached after Close() was never closed (leaked)")
	}
	if !fp.closed.Load() {
		t.Error("fd probe (stored before Close()) must still be closed by Close()")
	}
	if got, want := w.dropCounts(), (drops.Counts{Ringbuf: 5, MapFull: 10}); got != want {
		t.Errorf("dropCounts() = %+v, want %+v (both the Close()-drained fd probe and the racing payload probe must be folded in)", got, want)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.payloadProbes) != 0 {
		t.Errorf("payloadProbes = %v, want empty (closed watcher must not store new probes)", w.payloadProbes)
	}
}

// TestDefaultIsAlive_NonLinux checks that defaultIsAlive returns true on
// non-Linux systems where /proc does not exist — procFSAvailable is false
// and the function must not call os.Stat.
func TestDefaultIsAlive_NonLinux(t *testing.T) {
	orig := procFSAvailable
	procFSAvailable = false
	defer func() { procFSAvailable = orig }()
	if !defaultIsAlive(1) {
		t.Error("defaultIsAlive must return true on non-Linux where /proc is absent")
	}
}

// TestSSLWatcher_MaybeAttach_SkipsDeadProcessAfterFind verifies that the
// goroutine returns without calling attach when isAlive reports false after
// findWithRetry succeeds — avoiding a wasted BPF load for a process that
// died between find and attach.
func TestSSLWatcher_MaybeAttach_SkipsDeadProcessAfterFind(t *testing.T) {
	aliveCalled := make(chan struct{})
	var once sync.Once
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.isAlive = func(uint32) bool {
		once.Do(func() { close(aliveCalled) })
		return false
	}
	w.attach = func(pid uint32, path string) (sslProbe, error) {
		t.Fatal("attach must not be called for a dead process")
		return nil, nil
	}

	w.OnEvent(&events.Event{Pid: 42})
	waitOnChan(t, aliveCalled)

	w.mu.Lock()
	_, hasProbe := w.probes[42]
	w.mu.Unlock()
	if hasProbe {
		t.Error("probe was stored for a process that was dead after findWithRetry")
	}
}

// TestSSLWatcher_Reaper_TickerCallsReapDeadProbes confirms that runReaper
// invokes reapDeadProbes via the ticker, not only via the direct-call path
// exercised by the other reaper tests.
func TestSSLWatcher_Reaper_TickerCallsReapDeadProbes(t *testing.T) {
	orig := reaperInterval
	reaperInterval = time.Millisecond
	defer func() { reaperInterval = orig }()

	fp := &fakeProbe{}
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	w.mu.Lock()
	w.probes[66] = fp
	w.seen[66] = true
	w.mu.Unlock()

	w.isAlive = func(pid uint32) bool { return pid != 66 }

	deadline := time.Now().Add(2 * time.Second)
	for !fp.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !fp.closed.Load() {
		t.Error("runReaper did not close the dead-process probe via the ticker")
	}
}

// TestSSLWatcher_Reaper_NoopWhenClosed confirms that reapDeadProbes returns
// immediately when the watcher is already closed — the guard prevents
// redundant map access on a shut-down watcher.
func TestSSLWatcher_Reaper_NoopWhenClosed(t *testing.T) {
	fp := &fakeProbe{}
	w := newSSLWatcher(&fakeSink{})
	w.mu.Lock()
	w.probes[55] = fp
	w.seen[55] = true
	w.mu.Unlock()
	w.isAlive = func(uint32) bool { return false }

	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	w.reapDeadProbes() // must be a no-op: closed guard returns before any map access
}

// TestSSLWatcher_Reaper_LogsCloseError confirms that a Close() error from a
// probe does not panic the reaper — the error is logged and execution
// continues.
func TestSSLWatcher_Reaper_LogsCloseError(t *testing.T) {
	fp := &fakeProbe{closeErr: errors.New("close failed")}
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	w.mu.Lock()
	w.probes[77] = fp
	w.seen[77] = true
	w.mu.Unlock()

	w.isAlive = func(pid uint32) bool { return pid != 77 }
	w.reapDeadProbes() // must log the error without panicking
}
