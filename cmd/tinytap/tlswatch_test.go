package main

import (
	"bytes"
	"errors"
	"io"
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

// fakeCloser is an io.Closer stand-in for a per-pid uprobe link set.
// closed uses atomic.Bool since tests that race Close() against an in-flight
// attach read it from a polling loop concurrently with the watcher's
// background goroutine writing it.
type fakeCloser struct {
	closeErr error
	closed   atomic.Bool
}

func (f *fakeCloser) Close() error {
	f.closed.Store(true)
	return f.closeErr
}

// fakeSSLObjects implements sslObjects. reader defaults to an empty
// fakeReader (returns EOF immediately, so any spawned captureTLS goroutine
// exits right away without needing explicit teardown in tests that don't
// care about its behavior). AttachSetFd/AttachPayload default to succeeding
// with a fresh *fakeCloser each call; tests override *Fn to inject errors or
// synchronize with an in-flight attach.
type fakeSSLObjects struct {
	rd              ringbufReader
	dropCounts      drops.Counts
	lookupFd        int32
	lookupOK        bool
	attachSetFdFn   func(pid uint32, path string) (io.Closer, error)
	attachPayloadFn func(pid uint32, path string) (io.Closer, error)
	deletedPids     []map[uint32]bool
}

func (f *fakeSSLObjects) Lookup(uint32, uint64) (int32, bool) { return f.lookupFd, f.lookupOK }

func (f *fakeSSLObjects) Delete(uint32, uint64) {}

func (f *fakeSSLObjects) DeletePids(dead map[uint32]bool) int {
	f.deletedPids = append(f.deletedPids, dead)
	return len(dead)
}

func (f *fakeSSLObjects) DropCounts() drops.Counts { return f.dropCounts }

func (f *fakeSSLObjects) reader() ringbufReader {
	if f.rd != nil {
		return f.rd
	}
	return &fakeReader{}
}

func (f *fakeSSLObjects) AttachSetFd(pid uint32, path string) (io.Closer, error) {
	if f.attachSetFdFn != nil {
		return f.attachSetFdFn(pid, path)
	}
	return &fakeCloser{}, nil
}

func (f *fakeSSLObjects) AttachPayload(pid uint32, path string) (io.Closer, error) {
	if f.attachPayloadFn != nil {
		return f.attachPayloadFn(pid, path)
	}
	return &fakeCloser{}, nil
}

// fakeSSLRegistry implements sslRegistryCloser for tests that need Close()
// to fail without constructing a real (privileged) *loader.SSLRegistry.
type fakeSSLRegistry struct{ closeErr error }

func (f *fakeSSLRegistry) Close() error { return f.closeErr }

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

// TestNewSSLWatcher_DefaultFindAndShared exercises the real (non-injected)
// find/shared closures newSSLWatcher wires up by default — every other test
// in this file overrides w.find/w.shared before use. Both real functions
// fail fast without root: tls.Find on a pid unlikely to have libssl mapped,
// and the registry's Shared on a nonexistent path (which fails at the
// os.Stat check before touching eBPF).
func TestNewSSLWatcher_DefaultFindAndShared(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	if _, err := w.find(uint32(os.Getpid())); err == nil {
		t.Error("find(own pid) = nil error, want an error (no libssl expected in this test binary)")
	}
	if _, _, err := w.shared("/nonexistent-path-xyz"); err == nil {
		t.Error("shared(nonexistent path) = nil error, want an error")
	}
}

// TestNewSSLWatcher_DefaultShared_WrapsSuccess exercises the default shared
// closure's success path — the one line that only runs when
// loader.SSLRegistry.Shared itself succeeds, which needs real eBPF and so
// can't be reached through the nonexistent-path failure case
// TestNewSSLWatcher_DefaultFindAndShared already covers. sslRegistryShared is
// swapped for a fake that returns a real (never-loaded) zero-value
// *loader.SSLObjects, proving the wrap into sslObjectsAdapter itself is
// correct without touching a kernel.
func TestNewSSLWatcher_DefaultShared_WrapsSuccess(t *testing.T) {
	orig := sslRegistryShared
	defer func() { sslRegistryShared = orig }()
	want := &loader.SSLObjects{}
	sslRegistryShared = func(*loader.SSLRegistry, string) (*loader.SSLObjects, bool, error) {
		return want, true, nil
	}

	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	obj, created, err := w.shared("/lib/libssl.so.3")
	if err != nil {
		t.Fatalf("shared() = %v, want nil error", err)
	}
	if !created {
		t.Error("shared() created = false, want true")
	}
	adapter, ok := obj.(sslObjectsAdapter)
	if !ok || adapter.SSLObjects != want {
		t.Errorf("shared() = %#v, want sslObjectsAdapter wrapping %#v", obj, want)
	}
}

// TestSSLObjectsAdapter_Reader confirms the adapter delegates to the wrapped
// *loader.SSLObjects's Reader field — the one-line bridge that lets
// sslObjects (a method-only interface) stand in for a struct field Go
// interfaces can't require directly (mirrors bpfSession's reader() pattern
// in bpf.go).
func TestSSLObjectsAdapter_Reader(t *testing.T) {
	inner := &loader.SSLObjects{}
	a := sslObjectsAdapter{inner}
	if got := a.reader(); got != ringbufReader(inner.Reader) {
		t.Errorf("reader() = %v, want the wrapped object's Reader field", got)
	}
}

// TestSSLObjectsAdapter_AttachSetFd_DelegatesToLoader and
// TestSSLObjectsAdapter_AttachPayload_DelegatesToLoader confirm the adapter
// calls through to loader.AttachSSLSetFd/AttachSSLReadWrite rather than some
// other path — using a nonexistent libssl path is enough to observe an
// error without needing root or real eBPF.
func TestSSLObjectsAdapter_AttachSetFd_DelegatesToLoader(t *testing.T) {
	a := sslObjectsAdapter{&loader.SSLObjects{}}
	if _, err := a.AttachSetFd(1, "/nonexistent-path-xyz"); err == nil {
		t.Error("AttachSetFd(nonexistent path) = nil error, want an error")
	}
}

func TestSSLObjectsAdapter_AttachPayload_DelegatesToLoader(t *testing.T) {
	a := sslObjectsAdapter{&loader.SSLObjects{}}
	if _, err := a.AttachPayload(1, "/nonexistent-path-xyz"); err == nil {
		t.Error("AttachPayload(nonexistent path) = nil error, want an error")
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
	w.shared = func(path string) (sslObjects, bool, error) {
		t.Fatal("shared should not be called when find fails")
		return nil, false, nil
	}

	w.OnEvent(&events.Event{Pid: 7})
	waitOnChan(t, calls)

	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.attached) != 0 {
		t.Errorf("attached = %v, want empty", w.attached)
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
	if len(w.attached) != 0 {
		t.Errorf("attached = %v, want empty", w.attached)
	}
}

func TestSSLWatcher_OnEvent_ClosedDuringAttach(t *testing.T) {
	attaching := make(chan struct{})
	release := make(chan struct{})
	linkCloser := &fakeCloser{}
	obj := &fakeSSLObjects{dropCounts: drops.Counts{Ringbuf: 3, MapFull: 5}}
	obj.attachSetFdFn = func(pid uint32, path string) (io.Closer, error) {
		close(attaching)
		<-release
		return linkCloser, nil
	}
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.shared = func(path string) (sslObjects, bool, error) { return obj, true, nil }

	w.OnEvent(&events.Event{Pid: 23})
	<-attaching // attach is in flight; Close() races it below

	if err := w.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	close(release) // let the in-flight attach complete after Close() returned

	deadline := time.Now().Add(2 * time.Second)
	for !linkCloser.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !linkCloser.closed.Load() {
		t.Error("link attached after Close() was never closed (leaked)")
	}
	if got, want := w.dropCounts(), (drops.Counts{Ringbuf: 3, MapFull: 5}); got != want {
		t.Errorf("dropCounts() = %+v, want %+v (racing object's counts must be folded into closedDrops)", got, want)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.attached) != 0 {
		t.Errorf("attached = %v, want empty (closed watcher must not store new attachments)", w.attached)
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
	if len(w.attached) != 0 {
		t.Errorf("attached = %v, want empty", w.attached)
	}
}

// TestSSLWatcher_OnEvent_SharedError confirms a failure loading the shared
// SSL uprobe objects (e.g. a symbol resolution error for this specific
// libssl build) is logged and the goroutine exits cleanly, without ever
// reaching AttachSetFd.
func TestSSLWatcher_OnEvent_SharedError(t *testing.T) {
	calls := make(chan struct{}, 1)
	sharedErr := errors.New("load SSL objects fail")
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.shared = func(path string) (sslObjects, bool, error) {
		defer close(calls)
		return nil, false, sharedErr
	}

	w.OnEvent(&events.Event{Pid: 35})
	waitOnChan(t, calls)

	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.attached) != 0 || len(w.caps) != 0 {
		t.Errorf("attached=%v caps=%v, want both empty", w.attached, w.caps)
	}
}

// TestSSLWatcher_OnEvent_ClosedWhileObjectsCreating races Close() against
// the moment maybeAttach learns it just created a new shared object (before
// it has stored anything in caps or spawned captureTLS) — distinct from
// TestSSLWatcher_OnEvent_ClosedDuringAttach, which races the later
// AttachSetFd stage instead.
func TestSSLWatcher_OnEvent_ClosedWhileObjectsCreating(t *testing.T) {
	reachedShared := make(chan struct{})
	release := make(chan struct{})
	obj := &fakeSSLObjects{}
	obj.attachSetFdFn = func(pid uint32, path string) (io.Closer, error) {
		t.Error("AttachSetFd must not be called when Close() won the race with object creation")
		return nil, errors.New("unexpected")
	}
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.shared = func(path string) (sslObjects, bool, error) {
		close(reachedShared)
		<-release
		return obj, true, nil
	}

	w.OnEvent(&events.Event{Pid: 37})
	<-reachedShared

	if err := w.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	close(release)

	// Give the goroutine a moment to observe w.closed and return before
	// asserting nothing leaked into caps/attached.
	time.Sleep(50 * time.Millisecond)

	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.caps) != 0 {
		t.Errorf("caps = %v, want empty (closed watcher must not register a newly created object)", w.caps)
	}
	if len(w.attached) != 0 {
		t.Errorf("attached = %v, want empty", w.attached)
	}
}

func TestSSLWatcher_OnEvent_Success(t *testing.T) {
	calls := make(chan struct{}, 1)
	payloadCalls := make(chan struct{}, 1)
	fdCloser := &fakeCloser{}
	payloadCloser := &fakeCloser{}
	obj := &fakeSSLObjects{}
	obj.attachSetFdFn = func(pid uint32, path string) (io.Closer, error) {
		defer close(calls)
		if path != "/lib/libssl.so.3" {
			t.Errorf("AttachSetFd path = %q, want /lib/libssl.so.3", path)
		}
		return fdCloser, nil
	}
	obj.attachPayloadFn = func(pid uint32, path string) (io.Closer, error) {
		defer close(payloadCalls)
		if path != "/lib/libssl.so.3" {
			t.Errorf("AttachPayload path = %q, want /lib/libssl.so.3", path)
		}
		return payloadCloser, nil
	}
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.shared = func(path string) (sslObjects, bool, error) { return obj, true, nil }

	w.OnEvent(&events.Event{Pid: 11})
	waitOnChan(t, calls)
	waitOnChan(t, payloadCalls)

	w.mu.Lock()
	att, ok := w.attached[11]
	_, hasCaps := w.caps[obj]
	w.mu.Unlock()
	if !ok || att.fdLinks != fdCloser {
		t.Errorf("attached[11].fdLinks = %v, %v; want %v, true", att, ok, fdCloser)
	}
	if !ok || att.payload != payloadCloser {
		t.Errorf("attached[11].payload = %v; want %v", att, payloadCloser)
	}
	if !hasCaps {
		t.Error("caps missing entry for the shared object")
	}
}

func TestSSLWatcher_OnEvent_AttachError(t *testing.T) {
	calls := make(chan struct{}, 1)
	obj := &fakeSSLObjects{}
	obj.attachSetFdFn = func(pid uint32, path string) (io.Closer, error) {
		defer close(calls)
		return nil, errors.New("attach fail")
	}
	obj.attachPayloadFn = func(pid uint32, path string) (io.Closer, error) {
		t.Fatal("AttachPayload should not be called when the fd attach fails")
		return nil, nil
	}
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.shared = func(path string) (sslObjects, bool, error) { return obj, true, nil }

	w.OnEvent(&events.Event{Pid: 13})
	waitOnChan(t, calls)

	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.attached) != 0 {
		t.Errorf("attached = %v, want empty", w.attached)
	}
}

// TestSSLWatcher_OnEvent_PayloadAttachErrorKeepsFdProbe confirms a
// payload-attach failure is logged and skipped without rolling back the
// already-stored fd link — fd correlation (#147) stays useful even when
// plaintext capture (#146) can't attach.
func TestSSLWatcher_OnEvent_PayloadAttachErrorKeepsFdProbe(t *testing.T) {
	calls := make(chan struct{}, 1)
	fdCloser := &fakeCloser{}
	obj := &fakeSSLObjects{}
	obj.attachSetFdFn = func(pid uint32, path string) (io.Closer, error) { return fdCloser, nil }
	obj.attachPayloadFn = func(pid uint32, path string) (io.Closer, error) {
		defer close(calls)
		return nil, errors.New("payload attach fail")
	}
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.shared = func(path string) (sslObjects, bool, error) { return obj, true, nil }

	w.OnEvent(&events.Event{Pid: 17})
	waitOnChan(t, calls)

	w.mu.Lock()
	defer w.mu.Unlock()
	att, ok := w.attached[17]
	if !ok || att.fdLinks != fdCloser {
		t.Errorf("attached[17].fdLinks = %v, %v; want %v, true (fd link kept despite payload attach failure)", att, ok, fdCloser)
	}
	if ok && att.payload != nil {
		t.Errorf("attached[17].payload = %v, want nil", att.payload)
	}
}

func TestSSLWatcher_OnEvent_ClosedDuringPayloadAttach(t *testing.T) {
	attaching := make(chan struct{})
	release := make(chan struct{})
	fdCloser := &fakeCloser{}
	payloadCloser := &fakeCloser{}
	obj := &fakeSSLObjects{dropCounts: drops.Counts{Ringbuf: 1, MapFull: 2}}
	obj.attachSetFdFn = func(pid uint32, path string) (io.Closer, error) { return fdCloser, nil }
	obj.attachPayloadFn = func(pid uint32, path string) (io.Closer, error) {
		close(attaching)
		<-release
		return payloadCloser, nil
	}
	w := newSSLWatcher(&fakeSink{})
	w.isAlive = func(uint32) bool { return true }
	w.find = func(pid uint32) (tls.Discovery, error) {
		return tls.Discovery{Pid: pid, Path: "/lib/libssl.so.3"}, nil
	}
	w.shared = func(path string) (sslObjects, bool, error) { return obj, true, nil }

	w.OnEvent(&events.Event{Pid: 29})
	<-attaching // payload attach is in flight; Close() races it below

	if err := w.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	close(release) // let the in-flight attach complete after Close() returned

	deadline := time.Now().Add(2 * time.Second)
	for !payloadCloser.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !payloadCloser.closed.Load() {
		t.Error("payload link attached after Close() was never closed (leaked)")
	}
	if !fdCloser.closed.Load() {
		t.Error("fd link (stored before Close()) must still be closed by Close()")
	}
	if got, want := w.dropCounts(), (drops.Counts{Ringbuf: 1, MapFull: 2}); got != want {
		t.Errorf("dropCounts() = %+v, want %+v (the shared object's counts must be folded in exactly once)", got, want)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.attached) != 0 {
		t.Errorf("attached = %v, want empty (closed watcher must not store new attachments)", w.attached)
	}
}

func TestSSLWatcher_Close_JoinsProbeAndSinkErrors(t *testing.T) {
	sinkErr := errors.New("sink close fail")
	fdErr := errors.New("fd link close fail")
	payloadErr := errors.New("payload link close fail")
	w := newSSLWatcher(&fakeSink{closeErr: sinkErr})
	fd1 := &fakeCloser{closeErr: fdErr}
	fd2 := &fakeCloser{}
	payload1 := &fakeCloser{closeErr: payloadErr}
	payload2 := &fakeCloser{}
	obj := &fakeSSLObjects{}
	w.attached[1] = &pidAttachment{obj: obj, fdLinks: fd1, payload: payload1}
	w.attached[2] = &pidAttachment{obj: obj, fdLinks: fd2, payload: payload2}

	err := w.Close()
	if err == nil {
		t.Fatal("Close() = nil, want error")
	}
	if !errors.Is(err, sinkErr) {
		t.Errorf("Close() error does not wrap sink close error: %v", err)
	}
	if !errors.Is(err, fdErr) {
		t.Errorf("Close() error does not wrap fd link close error: %v", err)
	}
	if !errors.Is(err, payloadErr) {
		t.Errorf("Close() error does not wrap payload link close error: %v", err)
	}
	if !fd1.closed.Load() || !fd2.closed.Load() {
		t.Errorf("fd1.closed=%v fd2.closed=%v, want both true", fd1.closed.Load(), fd2.closed.Load())
	}
	if !payload1.closed.Load() || !payload2.closed.Load() {
		t.Errorf("payload1.closed=%v payload2.closed=%v, want both true", payload1.closed.Load(), payload2.closed.Load())
	}
}

// TestSSLWatcher_Close_RegistryCloseError confirms an error closing the
// shared SSL registry is joined into Close()'s return value rather than
// silently dropped.
func TestSSLWatcher_Close_RegistryCloseError(t *testing.T) {
	regErr := errors.New("registry close fail")
	w := newSSLWatcher(&fakeSink{})
	w.reg = &fakeSSLRegistry{closeErr: regErr}

	err := w.Close()
	if !errors.Is(err, regErr) {
		t.Errorf("Close() error = %v, want it to wrap %v", err, regErr)
	}
}

func TestSSLWatcher_Close_NoProbes(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	if err := w.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

// TestSSLWatcher_Close_Idempotent checks that calling Close() more than once
// returns the same result instead of closing an already-closed stopReaper
// channel, which would panic.
func TestSSLWatcher_Close_Idempotent(t *testing.T) {
	sinkErr := errors.New("sink close fail")
	w := newSSLWatcher(&fakeSink{closeErr: sinkErr})

	first := w.Close()
	second := w.Close()

	if !errors.Is(first, sinkErr) {
		t.Errorf("first Close() = %v, want it to wrap %v", first, sinkErr)
	}
	if second != first {
		t.Errorf("second Close() = %v, want the same result as the first call (%v)", second, first)
	}
}

// TestSSLWatcher_Close_ConcurrentIsSafe checks that concurrent Close() calls
// don't race on closing stopReaper.
func TestSSLWatcher_Close_ConcurrentIsSafe(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})

	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = w.Close()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("Close() call %d = %v, want nil", i, err)
		}
	}
}

func TestSSLWatcher_DropCounts_Empty(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	if got := w.dropCounts(); got != (drops.Counts{}) {
		t.Errorf("dropCounts() = %+v, want zero value for a watcher with no shared objects", got)
	}
}

func TestSSLWatcher_DropCounts_SumsLiveTracers(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	obj1 := &fakeSSLObjects{dropCounts: drops.Counts{Ringbuf: 1, MapFull: 2}}
	obj2 := &fakeSSLObjects{dropCounts: drops.Counts{MapFull: 4}}
	w.caps[obj1] = newTLSStreams()
	w.caps[obj2] = newTLSStreams()

	got := w.dropCounts()
	want := drops.Counts{Ringbuf: 1, MapFull: 6}
	if got != want {
		t.Errorf("dropCounts() = %+v, want %+v (sum across every live shared object)", got, want)
	}
}

// TestSSLWatcher_DropCounts_SharedObjectCountedOnce guards against the
// regression sharing one BPF object across pids makes possible: summing
// dropCounts per pid (as the old per-pid-probe design did) would count the
// same drop_counters map twice when two pids share one libssl inode.
func TestSSLWatcher_DropCounts_SharedObjectCountedOnce(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	obj := &fakeSSLObjects{dropCounts: drops.Counts{Ringbuf: 5}}
	w.caps[obj] = newTLSStreams()
	w.attached[1] = &pidAttachment{obj: obj, fdLinks: &fakeCloser{}}
	w.attached[2] = &pidAttachment{obj: obj, fdLinks: &fakeCloser{}}

	got := w.dropCounts()
	want := drops.Counts{Ringbuf: 5}
	if got != want {
		t.Errorf("dropCounts() = %+v, want %+v (two pids sharing one object must count its drops once, not twice)", got, want)
	}
}

func TestSSLWatcher_DropCounts_RetainedAfterClose(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	obj1 := &fakeSSLObjects{dropCounts: drops.Counts{Ringbuf: 1, MapFull: 2}}
	obj2 := &fakeSSLObjects{dropCounts: drops.Counts{MapFull: 4}}
	w.caps[obj1] = newTLSStreams()
	w.caps[obj2] = newTLSStreams()
	want := drops.Counts{Ringbuf: 1, MapFull: 6}

	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}

	if got := w.dropCounts(); got != want {
		t.Errorf("dropCounts() after Close() = %+v, want %+v (counts must survive teardown)", got, want)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.attached != nil || w.caps != nil {
		t.Errorf("attached=%v caps=%v, want both nil after Close()", w.attached, w.caps)
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

// TestSSLWatcher_Reaper_ClosesLinksForDeadProcess verifies that
// reapDeadProbes closes both the fd link and the payload link when the
// monitored process has exited, reclaims its ssl_fd_map entries via
// DeletePids, and leaves the shared object (and its drop counters) alone —
// it outlives any individual pid.
func TestSSLWatcher_Reaper_ClosesLinksForDeadProcess(t *testing.T) {
	fdCloser := &fakeCloser{}
	payloadCloser := &fakeCloser{}
	obj := &fakeSSLObjects{dropCounts: drops.Counts{Ringbuf: 1, MapFull: 2}}
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	w.mu.Lock()
	w.caps[obj] = newTLSStreams()
	w.attached[99] = &pidAttachment{obj: obj, fdLinks: fdCloser, payload: payloadCloser}
	w.seen[99] = true
	w.mu.Unlock()

	w.isAlive = func(pid uint32) bool { return pid != 99 }
	w.reapDeadProbes()

	if !fdCloser.closed.Load() {
		t.Error("fd link was not closed by reaper")
	}
	if !payloadCloser.closed.Load() {
		t.Error("payload link was not closed by reaper")
	}
	if len(obj.deletedPids) != 1 || !obj.deletedPids[0][99] {
		t.Errorf("DeletePids not called with pid 99: %v", obj.deletedPids)
	}

	w.mu.Lock()
	_, hasSeen := w.seen[99]
	_, hasAttached := w.attached[99]
	_, hasCaps := w.caps[obj]
	harvested := w.closedDrops
	w.mu.Unlock()

	if hasSeen || hasAttached {
		t.Error("reaper did not remove dead pid from seen/attached maps")
	}
	if !hasCaps {
		t.Error("reaper must not remove the shared object's caps entry — it outlives individual pids")
	}
	if harvested != (drops.Counts{}) {
		t.Errorf("closedDrops = %+v, want zero (reaper must not harvest a still-live shared object — that would double-count on the next dropCounts() read)", harvested)
	}
}

// TestSSLWatcher_Reaper_ClosesOnlyFdLinkForDeadProcess confirms that the
// reaper also closes fd-only attachments (those where payload attachment
// failed, kept for fd correlation per #147) when the process exits.
func TestSSLWatcher_Reaper_ClosesOnlyFdLinkForDeadProcess(t *testing.T) {
	fdCloser := &fakeCloser{}
	obj := &fakeSSLObjects{}
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	w.mu.Lock()
	w.caps[obj] = newTLSStreams()
	w.attached[88] = &pidAttachment{obj: obj, fdLinks: fdCloser} // payload nil: attach failed
	w.seen[88] = true
	w.mu.Unlock()

	w.isAlive = func(pid uint32) bool { return pid != 88 }
	w.reapDeadProbes()

	if !fdCloser.closed.Load() {
		t.Error("fd-only link was not closed by reaper")
	}
	w.mu.Lock()
	_, hasSeen := w.seen[88]
	_, hasAttached := w.attached[88]
	w.mu.Unlock()
	if hasSeen || hasAttached {
		t.Error("reaper did not remove dead pid from seen/attached maps")
	}
}

// TestSSLWatcher_Reaper_SkipsLiveAttachedProcess confirms reapDeadProbes
// leaves a live pid's attachment untouched — both in the main sweep over
// w.attached and in the budgeted w.seen sweep, which must skip any pid
// still present in w.attached rather than re-checking it — while still
// reaping a dead pid attached at the same time.
func TestSSLWatcher_Reaper_SkipsLiveAttachedProcess(t *testing.T) {
	liveFd := &fakeCloser{}
	deadFd := &fakeCloser{}
	obj := &fakeSSLObjects{}
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	w.mu.Lock()
	w.caps[obj] = newTLSStreams()
	w.attached[44] = &pidAttachment{obj: obj, fdLinks: liveFd}
	w.attached[45] = &pidAttachment{obj: obj, fdLinks: deadFd}
	w.seen[44] = true
	w.seen[45] = true
	w.mu.Unlock()

	w.isAlive = func(pid uint32) bool { return pid == 44 }
	w.reapDeadProbes()

	if liveFd.closed.Load() {
		t.Error("reaper closed the live pid's link — must only reap dead processes")
	}
	if !deadFd.closed.Load() {
		t.Error("reaper did not close the dead pid's link")
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.attached[44]; !ok {
		t.Error("reaper removed the live pid's attachment")
	}
	if _, ok := w.seen[44]; !ok {
		t.Error("reaper removed the live pid from seen — must skip pids still in attached")
	}
	if _, ok := w.attached[45]; ok {
		t.Error("reaper did not remove the dead pid's attachment")
	}
	if _, ok := w.seen[45]; ok {
		t.Error("reaper did not remove the dead pid from seen")
	}
}

// TestSSLWatcher_Reaper_SeenSweepReclaimsOnlyDeadPids seeds a large number of
// seen-but-never-attached pids (the state left by find/attach failures,
// which deliberately keep seen[pid]=true to suppress retry storms) and
// confirms the budgeted sweep reclaims exactly the dead ones over a few
// ticks while never touching a live one.
func TestSSLWatcher_Reaper_SeenSweepReclaimsOnlyDeadPids(t *testing.T) {
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	const deadCount = 500
	const livePid = deadCount + 1
	w.mu.Lock()
	for pid := uint32(1); pid <= deadCount; pid++ {
		w.seen[pid] = true
	}
	w.seen[livePid] = true
	w.mu.Unlock()

	w.isAlive = func(pid uint32) bool { return pid == livePid }

	deadline := time.Now().Add(2 * time.Second)
	for {
		w.reapDeadProbes()
		w.mu.Lock()
		n := len(w.seen)
		w.mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.seen[livePid]; !ok {
		t.Error("seen sweep removed a live pid — must never do that")
	}
	if len(w.seen) != 1 {
		t.Errorf("len(seen) = %d, want 1 (only the live pid left after sweeping converges)", len(w.seen))
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
	w.shared = func(path string) (sslObjects, bool, error) {
		t.Error("shared must not be called when semaphore is full")
		return nil, false, errors.New("unexpected")
	}

	w.OnEvent(&events.Event{Pid: 31})
	waitOnChan(t, found)              // goroutine reached find()
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

// TestDefaultIsAlive_NotExist checks that a missing /proc/<pid> entry is
// treated as dead.
func TestDefaultIsAlive_NotExist(t *testing.T) {
	origAvail, origStat := procFSAvailable, statProcEntry
	procFSAvailable = true
	statProcEntry = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	defer func() { procFSAvailable, statProcEntry = origAvail, origStat }()

	if defaultIsAlive(1) {
		t.Error("defaultIsAlive must return false when /proc/<pid> does not exist")
	}
}

// TestDefaultIsAlive_OtherStatError checks that a stat error other than
// os.ErrNotExist (e.g. permission denied under /proc hidepid) is treated as
// alive, since we can't actually tell whether the process is dead.
func TestDefaultIsAlive_OtherStatError(t *testing.T) {
	origAvail, origStat := procFSAvailable, statProcEntry
	procFSAvailable = true
	statProcEntry = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
	defer func() { procFSAvailable, statProcEntry = origAvail, origStat }()

	if !defaultIsAlive(1) {
		t.Error("defaultIsAlive must return true on a non-not-exist stat error")
	}
}

// TestSSLWatcher_MaybeAttach_SkipsDeadProcessAfterFind verifies that the
// goroutine returns without calling shared when isAlive reports false after
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
	w.shared = func(path string) (sslObjects, bool, error) {
		t.Fatal("shared must not be called for a dead process")
		return nil, false, nil
	}

	w.OnEvent(&events.Event{Pid: 42})
	waitOnChan(t, aliveCalled)

	w.mu.Lock()
	_, hasAttached := w.attached[42]
	w.mu.Unlock()
	if hasAttached {
		t.Error("attachment was stored for a process that was dead after findWithRetry")
	}
}

// TestSSLWatcher_Reaper_TickerCallsReapDeadProbes confirms that runReaper
// invokes reapDeadProbes via the ticker, not only via the direct-call path
// exercised by the other reaper tests.
func TestSSLWatcher_Reaper_TickerCallsReapDeadProbes(t *testing.T) {
	orig := reaperInterval
	reaperInterval = time.Millisecond
	defer func() { reaperInterval = orig }()

	fdCloser := &fakeCloser{}
	obj := &fakeSSLObjects{}
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	w.mu.Lock()
	w.caps[obj] = newTLSStreams()
	w.attached[66] = &pidAttachment{obj: obj, fdLinks: fdCloser}
	w.seen[66] = true
	w.mu.Unlock()

	w.isAlive = func(pid uint32) bool { return pid != 66 }

	deadline := time.Now().Add(2 * time.Second)
	for !fdCloser.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !fdCloser.closed.Load() {
		t.Error("runReaper did not close the dead-process link via the ticker")
	}
}

// TestSSLWatcher_Reaper_NoopWhenClosed confirms that reapDeadProbes returns
// immediately when the watcher is already closed — the guard prevents
// redundant map access on a shut-down watcher.
func TestSSLWatcher_Reaper_NoopWhenClosed(t *testing.T) {
	fdCloser := &fakeCloser{}
	obj := &fakeSSLObjects{}
	w := newSSLWatcher(&fakeSink{})
	w.mu.Lock()
	w.caps[obj] = newTLSStreams()
	w.attached[55] = &pidAttachment{obj: obj, fdLinks: fdCloser}
	w.seen[55] = true
	w.mu.Unlock()
	w.isAlive = func(uint32) bool { return false }

	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	w.reapDeadProbes() // must be a no-op: closed guard returns before any map access
}

// TestSSLWatcher_Reaper_LogsCloseError confirms that a Close() error from a
// link does not panic the reaper — the error is logged and execution
// continues.
func TestSSLWatcher_Reaper_LogsCloseError(t *testing.T) {
	fdCloser := &fakeCloser{closeErr: errors.New("close failed")}
	obj := &fakeSSLObjects{}
	w := newSSLWatcher(&fakeSink{})
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	w.mu.Lock()
	w.caps[obj] = newTLSStreams()
	w.attached[77] = &pidAttachment{obj: obj, fdLinks: fdCloser}
	w.seen[77] = true
	w.mu.Unlock()

	w.isAlive = func(pid uint32) bool { return pid != 77 }
	w.reapDeadProbes() // must log the error without panicking
}
