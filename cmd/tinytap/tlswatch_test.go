package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shinagawa-web/tinytap/internal/events"
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

type fakeProbe struct {
	closeErr error
	closed   bool
}

func (f *fakeProbe) Close() error {
	f.closed = true
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
// find/attach closures newSSLWatcher wires up by default — every other test
// in this file overrides w.find/w.attach before use. Both real functions
// fail fast without root: tls.Find on a pid unlikely to have libssl mapped,
// and loader.AttachSSLSetFd on a nonexistent path (which fails at the
// os.Stat check before touching eBPF).
func TestNewSSLWatcher_DefaultFindAndAttach(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})

	if _, err := w.find(uint32(os.Getpid())); err == nil {
		t.Error("find(own pid) = nil error, want an error (no libssl expected in this test binary)")
	}
	if _, err := w.attach(1, "/nonexistent-path-xyz"); err == nil {
		t.Error("attach(nonexistent path) = nil error, want an error")
	}
}

func TestSSLWatcher_OnEvent_Dedup(t *testing.T) {
	calls := make(chan struct{}, 10)
	var findCount int
	w := newSSLWatcher(&fakeSink{})
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

func TestSSLWatcher_OnEvent_Success(t *testing.T) {
	calls := make(chan struct{}, 1)
	fp := &fakeProbe{}
	w := newSSLWatcher(&fakeSink{})
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

	w.OnEvent(&events.Event{Pid: 11})
	waitOnChan(t, calls)

	w.mu.Lock()
	stored, ok := w.probes[11]
	w.mu.Unlock()
	if !ok || stored != fp {
		t.Errorf("probes[11] = %v, %v; want %v, true", stored, ok, fp)
	}
}

func TestSSLWatcher_OnEvent_AttachError(t *testing.T) {
	calls := make(chan struct{}, 1)
	w := newSSLWatcher(&fakeSink{})
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.attach = func(pid uint32, path string) (sslProbe, error) {
		defer close(calls)
		return nil, errors.New("attach fail")
	}

	w.OnEvent(&events.Event{Pid: 13})
	waitOnChan(t, calls)

	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.probes) != 0 {
		t.Errorf("probes = %v, want empty", w.probes)
	}
}

func TestSSLWatcher_Close_JoinsProbeAndSinkErrors(t *testing.T) {
	sinkErr := errors.New("sink close fail")
	probeErr := errors.New("probe close fail")
	w := newSSLWatcher(&fakeSink{closeErr: sinkErr})
	fp1 := &fakeProbe{closeErr: probeErr}
	fp2 := &fakeProbe{}
	w.probes[1] = fp1
	w.probes[2] = fp2

	err := w.Close()
	if err == nil {
		t.Fatal("Close() = nil, want error")
	}
	if !errors.Is(err, sinkErr) {
		t.Errorf("Close() error does not wrap sink close error: %v", err)
	}
	if !fp1.closed || !fp2.closed {
		t.Errorf("fp1.closed=%v fp2.closed=%v, want both true", fp1.closed, fp2.closed)
	}
}

func TestSSLWatcher_Close_NoProbes(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	if err := w.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
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
