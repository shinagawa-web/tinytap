package main

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/config"
	"github.com/shinagawa-web/tinytap/internal/drops"
	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/output"
	httpproto "github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// fakeBPF implements bpfSession for testing.
type fakeBPF struct {
	rd       ringbufCloser
	closeErr error
	drops    drops.Counts
	dropsFn  func() drops.Counts
}

func (f *fakeBPF) reader() ringbufCloser { return f.rd }
func (f *fakeBPF) Close() error          { return f.closeErr }

func (f *fakeBPF) dropCounts() drops.Counts {
	if f.dropsFn != nil {
		return f.dropsFn()
	}
	return f.drops
}

var _ bpfSession = (*fakeBPF)(nil)

// fakeRingbufCloser implements ringbufCloser — returns EOF immediately on Read.
type fakeRingbufCloser struct {
	mu       sync.Mutex
	isClosed bool
	closeErr error
	closedCh chan struct{}
}

func newFakeRC() *fakeRingbufCloser {
	return &fakeRingbufCloser{closedCh: make(chan struct{})}
}

func newFakeRCWithErr(err error) *fakeRingbufCloser {
	return &fakeRingbufCloser{closedCh: make(chan struct{}), closeErr: err}
}

func (f *fakeRingbufCloser) Read() (ringbuf.Record, error) {
	return ringbuf.Record{}, errors.New("EOF")
}

func (f *fakeRingbufCloser) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.isClosed {
		f.isClosed = true
		close(f.closedCh)
	}
	return f.closeErr
}

// fakeTUISink implements tuiSink without a real terminal.
type fakeTUISink struct {
	runErr error
	quit   bool
	diags  []string
	drops  []uint64
}

func (f *fakeTUISink) OnEvent(*events.Event)          {}
func (f *fakeTUISink) OnMessage(httpproto.Message)    {}
func (f *fakeTUISink) OnPaired(httpproto.PairedEvent) {}
func (f *fakeTUISink) Close() error                   { return nil }
func (f *fakeTUISink) Run() error                     { return f.runErr }
func (f *fakeTUISink) Quit()                          { f.quit = true }
func (f *fakeTUISink) SendDiag(line string)           { f.diags = append(f.diags, line) }
func (f *fakeTUISink) SendDrops(n uint64)             { f.drops = append(f.drops, n) }

var _ output.Sink = (*fakeTUISink)(nil)
var _ tuiSink = (*fakeTUISink)(nil)

// --- tinytapSession ---

func TestTinytapSession_Reader(t *testing.T) {
	rd := newFakeRC()
	s := &tinytapSession{rd: rd, closer: &fakeSink{}}
	if s.reader() != rd {
		t.Error("want the injected reader")
	}
}

func TestTinytapSession_Close(t *testing.T) {
	s := &tinytapSession{rd: newFakeRC(), closer: &fakeSink{}}
	if err := s.Close(); err != nil {
		t.Fatalf("want nil error, got %v", err)
	}
}

func TestTinytapSession_CloseError(t *testing.T) {
	s := &tinytapSession{rd: newFakeRC(), closer: &fakeSink{closeErr: errors.New("boom")}}
	if err := s.Close(); err == nil {
		t.Error("want error from closer")
	}
}

func TestTinytapSession_DropCountsNil(t *testing.T) {
	s := &tinytapSession{rd: newFakeRC(), closer: &fakeSink{}}
	if got := s.dropCounts(); got != (drops.Counts{}) {
		t.Errorf("dropCounts() = %+v, want zero value when no counter source is wired", got)
	}
}

func TestTinytapSession_DropCounts(t *testing.T) {
	want := drops.Counts{Ringbuf: 2, MapFull: 3}
	s := &tinytapSession{rd: newFakeRC(), closer: &fakeSink{}, drops: func() drops.Counts { return want }}
	if got := s.dropCounts(); got != want {
		t.Errorf("dropCounts() = %+v, want %+v", got, want)
	}
}

// --- defaultNewTUISink / defaultNewStdoutSink ---

func TestDefaultNewTUISink(t *testing.T) {
	s := defaultNewTUISink(120, 24)
	if s == nil {
		t.Error("want non-nil tuiSink")
	}
}

func TestDefaultNewStdoutSink(t *testing.T) {
	s := defaultNewStdoutSink()
	if s == nil {
		t.Error("want non-nil stdout sink")
	}
}

// --- parseFlags ---

func TestParseFlags_Defaults(t *testing.T) {
	cfg, err := parseFlags([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.configPath != "" {
		t.Errorf("configPath = %q, want empty", cfg.configPath)
	}
	if cfg.showVersion {
		t.Error("want showVersion=false")
	}
}

func TestParseFlags_ConfigPath(t *testing.T) {
	cfg, err := parseFlags([]string{"--config", "/tmp/custom.toml"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.configPath != "/tmp/custom.toml" {
		t.Errorf("configPath = %q, want /tmp/custom.toml", cfg.configPath)
	}
}

func TestParseFlags_UnknownFlag(t *testing.T) {
	_, err := parseFlags([]string{"--nonexistent"})
	if err == nil {
		t.Error("want error for unknown flag")
	}
}

func TestParseFlags_Version(t *testing.T) {
	cfg, err := parseFlags([]string{"--version"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.showVersion {
		t.Error("want showVersion=true")
	}
}

// --- run() ---

func TestRun_ParseFlagsError(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap", "--nonexistent"}
	defer func() { os.Args = old }()

	if err := run(); err == nil {
		t.Error("want error for unknown flag")
	}
}

func TestRun_Version(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap", "--version"}
	defer func() { os.Args = old }()

	// loadBPF must not be called for --version — it should exit before any
	// eBPF loading, so it works without root or capabilities.
	oldLoad := loadBPF
	loadBPF = func(uint32) (bpfSession, error) {
		t.Fatal("loadBPF must not be called for --version")
		return nil, nil
	}
	defer func() { loadBPF = oldLoad }()

	if err := run(); err != nil {
		t.Fatalf("want nil error, got %v", err)
	}
}

func TestRun_ConfigError(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap"}
	defer func() { os.Args = old }()

	oldLoadConfig := loadConfig
	loadConfig = func(string) (config.Config, error) { return config.Config{}, errors.New("bad config") }
	defer func() { loadConfig = oldLoadConfig }()

	if err := run(); err == nil {
		t.Error("want error from loadConfig")
	}
}

func TestRun_PassesConfigPathToLoadConfig(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap", "--config", "/some/path.toml"}
	defer func() { os.Args = old }()

	var gotPath string
	oldLoadConfig := loadConfig
	loadConfig = func(path string) (config.Config, error) {
		gotPath = path
		return config.Config{}, errors.New("stop here")
	}
	defer func() { loadConfig = oldLoadConfig }()

	_ = run()
	if gotPath != "/some/path.toml" {
		t.Errorf("loadConfig called with %q, want /some/path.toml", gotPath)
	}
}

func TestRun_OutputExit(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap"}
	defer func() { os.Args = old }()

	oldLoadConfig := loadConfig
	loadConfig = func(string) (config.Config, error) { return config.Config{Output: "auto"}, nil }
	defer func() { loadConfig = oldLoadConfig }()

	oldFn := isTerminalFn
	isTerminalFn = func(int) bool { return false }
	defer func() { isTerminalFn = oldFn }()

	err := run()
	if !errors.Is(err, errSilentExit) {
		t.Errorf("want errSilentExit, got %v", err)
	}
}

func TestRun_LoadBPFError(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap"}
	defer func() { os.Args = old }()

	oldLoadConfig := loadConfig
	loadConfig = func(string) (config.Config, error) { return config.Config{Output: "stdout"}, nil }
	defer func() { loadConfig = oldLoadConfig }()

	oldLoad := loadBPF
	loadBPF = func(uint32) (bpfSession, error) { return nil, errors.New("no eBPF") }
	defer func() { loadBPF = oldLoad }()

	if err := run(); err == nil {
		t.Error("want error from loadBPF")
	}
}

func TestRun_TeardownError(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap"}
	defer func() { os.Args = old }()

	oldLoadConfig := loadConfig
	loadConfig = func(string) (config.Config, error) { return config.Config{Output: "stdout"}, nil }
	defer func() { loadConfig = oldLoadConfig }()

	oldLoad := loadBPF
	loadBPF = func(uint32) (bpfSession, error) {
		return &fakeBPF{rd: newFakeRC(), closeErr: errors.New("teardown err")}, nil
	}
	defer func() { loadBPF = oldLoad }()

	oldRun := doRunStdout
	doRunStdout = func(bpfSession) {}
	defer func() { doRunStdout = oldRun }()

	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func TestRun_RoutesToStdout(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap"}
	defer func() { os.Args = old }()

	oldLoadConfig := loadConfig
	loadConfig = func(string) (config.Config, error) { return config.Config{Output: "stdout"}, nil }
	defer func() { loadConfig = oldLoadConfig }()

	oldLoad := loadBPF
	loadBPF = func(uint32) (bpfSession, error) { return &fakeBPF{rd: newFakeRC()}, nil }
	defer func() { loadBPF = oldLoad }()

	called := false
	oldRun := doRunStdout
	doRunStdout = func(bpfSession) { called = true }
	defer func() { doRunStdout = oldRun }()

	if err := run(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("want doRunStdout called")
	}
}

func TestRun_RoutesToTUI(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap"}
	defer func() { os.Args = old }()

	oldLoadConfig := loadConfig
	loadConfig = func(string) (config.Config, error) { return config.Config{Output: "auto"}, nil }
	defer func() { loadConfig = oldLoadConfig }()

	oldIsTerminal := isTerminalFn
	isTerminalFn = func(int) bool { return true }
	defer func() { isTerminalFn = oldIsTerminal }()

	oldGetSize := getSizeFn
	getSizeFn = func(int) (int, int, error) { return 200, 50, nil }
	defer func() { getSizeFn = oldGetSize }()

	oldLoad := loadBPF
	loadBPF = func(uint32) (bpfSession, error) { return &fakeBPF{rd: newFakeRC()}, nil }
	defer func() { loadBPF = oldLoad }()

	called := false
	oldRun := doRunTUI
	doRunTUI = func(bpfSession, int, int) { called = true }
	defer func() { doRunTUI = oldRun }()

	if err := run(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("want doRunTUI called")
	}
}

// --- closeOnInterrupt ---

func TestCloseOnInterrupt_NoError(t *testing.T) {
	rd := newFakeRC()
	stop := make(chan os.Signal, 1)
	closeOnInterrupt(rd, stop)
	stop <- os.Interrupt
	select {
	case <-rd.closedCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}

func TestCloseOnInterrupt_WithError(t *testing.T) {
	rd := newFakeRCWithErr(errors.New("close err"))
	stop := make(chan os.Signal, 1)
	closeOnInterrupt(rd, stop)
	stop <- os.Interrupt
	select {
	case <-rd.closedCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}

// --- runStdout ---

func TestRunStdout_Completes(t *testing.T) {
	rd := newFakeRC()

	oldSink := newStdoutSink
	newStdoutSink = func() output.Sink { return &fakeSink{} }
	defer func() { newStdoutSink = oldSink }()

	runStdout(&fakeBPF{rd: rd})
}

// blockingRingbufCloser blocks Read() until Close() is called, like the real
// cilium/ebpf ringbuf.Reader does while waiting for data. Unlike
// fakeRingbufCloser (which errors on the very first Read, so capture's loop
// exits on its own regardless of any signal), this proves it is genuinely
// the signal — via closeOnInterrupt calling Close() — that unblocks capture,
// not an incidental property of the fake.
//
// readyCh closes on the first Read() call, giving tests a deterministic
// "runStdout has reached capture's read loop" signal — and since
// signal.Notify runs strictly before that call in runStdout's body, this
// also guarantees the signal handler is already registered, without relying
// on a fixed sleep that could race under a loaded scheduler (e.g. CI).
type blockingRingbufCloser struct {
	closedCh chan struct{}
	readyCh  chan struct{}
	readOnce sync.Once
}

func newBlockingRC() *blockingRingbufCloser {
	return &blockingRingbufCloser{closedCh: make(chan struct{}), readyCh: make(chan struct{})}
}

func (b *blockingRingbufCloser) Read() (ringbuf.Record, error) {
	b.readOnce.Do(func() { close(b.readyCh) })
	<-b.closedCh
	return ringbuf.Record{}, errors.New("closed")
}

func (b *blockingRingbufCloser) Close() error {
	select {
	case <-b.closedCh:
	default:
		close(b.closedCh)
	}
	return nil
}

// #154: runStdout must register for both SIGINT and SIGTERM, so a real OS
// signal from an external supervisor or test harness (not just a value
// pushed onto a channel in a unit test) reliably closes the ringbuf reader
// before the process exits. Sends an actual signal to this test process via
// syscall.Kill, run sequentially (no t.Parallel) so one test's leftover
// signal registration can't race the next.
func TestRunStdout_RealSIGINTTriggersShutdown(t *testing.T) {
	testRunStdoutRealSignal(t, syscall.SIGINT)
}

func TestRunStdout_RealSIGTERMTriggersShutdown(t *testing.T) {
	testRunStdoutRealSignal(t, syscall.SIGTERM)
}

func testRunStdoutRealSignal(t *testing.T, sig syscall.Signal) {
	rd := newBlockingRC()

	oldSink := newStdoutSink
	newStdoutSink = func() output.Sink { return &fakeSink{} }
	defer func() { newStdoutSink = oldSink }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runStdout(&fakeBPF{rd: rd})
	}()

	// Wait for runStdout to reach capture's Read() call — signal.Notify runs
	// strictly before that in runStdout's body, so this deterministically
	// guarantees the handler is registered before the signal is sent.
	select {
	case <-rd.readyCh:
	case <-time.After(2 * time.Second):
		t.Fatal("runStdout never reached capture's read loop")
	}
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("runStdout did not return after a real %v", sig)
	}
}

// --- runCapturePipeline ---

func TestRunCapturePipeline_NoError(t *testing.T) {
	rd := newFakeRC()
	err := runCapturePipeline(rd, &fakeSink{}, &fakeTUISink{})
	if err != nil {
		t.Errorf("want nil, got %v", err)
	}
	rd.mu.Lock()
	closed := rd.isClosed
	rd.mu.Unlock()
	if !closed {
		t.Error("want rd closed after Run returns")
	}
}

func TestRunCapturePipeline_UIError(t *testing.T) {
	rd := newFakeRC()
	err := runCapturePipeline(rd, &fakeSink{}, &fakeTUISink{runErr: errors.New("tui failed")})
	if err == nil {
		t.Error("want error from ui.Run")
	}
}

func TestRunCapturePipeline_CloseError(t *testing.T) {
	rd := newFakeRCWithErr(errors.New("close err"))
	err := runCapturePipeline(rd, &fakeSink{}, &fakeTUISink{})
	if err != nil {
		t.Errorf("want nil runErr, got %v", err)
	}
}

// --- runTUI ---

func TestRunTUI_Completes(t *testing.T) {
	rd := newFakeRC()
	fakeTUI := &fakeTUISink{}

	oldNew := newTUISink
	newTUISink = func(int, int) tuiSink { return fakeTUI }
	defer func() { newTUISink = oldNew }()

	runTUI(&fakeBPF{rd: rd}, 120, 24)
}

func TestRunTUI_LogsUIError(t *testing.T) {
	rd := newFakeRC()
	fakeTUI := &fakeTUISink{runErr: errors.New("tui failed")}

	oldNew := newTUISink
	newTUISink = func(int, int) tuiSink { return fakeTUI }
	defer func() { newTUISink = oldNew }()

	runTUI(&fakeBPF{rd: rd}, 120, 24)
}

// A stray log line during the TUI session (#216) — here, runCapturePipeline's
// "close reader" log when rd.Close() errors — is routed to the TUI sink's
// diagnostics panel instead of the alt-screen, and flushed to stderr once the
// session ends so it isn't lost if the user never opened the panel.
func TestRunTUI_RoutesLogIntoDiagBufferAndFlushesOnExit(t *testing.T) {
	rd := newFakeRCWithErr(errors.New("boom"))
	fakeTUI := &fakeTUISink{}

	oldNew := newTUISink
	newTUISink = func(int, int) tuiSink { return fakeTUI }
	defer func() { newTUISink = oldNew }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	runTUI(&fakeBPF{rd: rd}, 120, 24)

	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close pipe writer: %v", closeErr)
	}
	out, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatalf("read pipe: %v", readErr)
	}

	if len(fakeTUI.diags) == 0 {
		t.Fatal("want at least one diag line routed to the TUI sink")
	}
	if !strings.Contains(fakeTUI.diags[0], "close reader") {
		t.Errorf("diag line = %q, want it to mention the close-reader error", fakeTUI.diags[0])
	}
	if !strings.Contains(string(out), "close reader") {
		t.Errorf("stderr after the TUI exits = %q, want the diagnostic flushed there", out)
	}
}

// --- isRoutineTLSAttach ---

func TestIsRoutineTLSAttach(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"fd probe attached", "tls: SSL_set_fd uprobe attached for pid 123 (/lib/libssl.so.3)", true},
		{"payload probes attached", "tls: SSL_write/SSL_read/SSL_free uprobes attached for pid 123 (/lib/libssl.so.3)", true},
		{"discover failure", "tls: discover libssl for pid 123: scan /proc/123/maps: no such process", false},
		{"attach failure", "tls: attach SSL_set_fd for pid 123 (/lib/libssl.so.3): permission denied", false},
		{"unrelated line", "close reader: boom", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isRoutineTLSAttach(c.line); got != c.want {
				t.Errorf("isRoutineTLSAttach(%q) = %v, want %v", c.line, got, c.want)
			}
		})
	}
}

// --- closeSink ---

func TestCloseSink_NoError(t *testing.T) {
	closeSink(&fakeSink{})
}

func TestCloseSink_WithError(t *testing.T) {
	closeSink(&fakeSink{closeErr: errors.New("close failed")})
}

// --- reportDrops ---

func TestReportDrops_Zero(t *testing.T) {
	var buf bytes.Buffer
	oldOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOut)

	sess := &fakeBPF{}
	w := newSSLWatcher(&fakeSink{})

	reportDrops(sess, w)

	if buf.Len() != 0 {
		t.Errorf("reportDrops logged %q, want nothing when nothing dropped", buf.String())
	}
}

func TestReportDrops_NonZero(t *testing.T) {
	var buf bytes.Buffer
	oldOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOut)

	sess := &fakeBPF{drops: drops.Counts{Ringbuf: 2, MapFull: 3}}
	w := newSSLWatcher(&fakeSink{})

	reportDrops(sess, w)

	got := buf.String()
	if !strings.Contains(got, "drops:") {
		t.Errorf("reportDrops logged %q, want it to contain a drops summary", got)
	}
	if !strings.Contains(got, "ring buffer full: 2") || !strings.Contains(got, "state map full: 3") {
		t.Errorf("reportDrops logged %q, want it to include the session's counts", got)
	}
}

// --- pollDrops ---

func TestPollDrops_SendsOnChange(t *testing.T) {
	var mu sync.Mutex
	var total uint64
	sess := &fakeBPF{dropsFn: func() drops.Counts {
		mu.Lock()
		defer mu.Unlock()
		return drops.Counts{Ringbuf: total}
	}}
	w := newSSLWatcher(&fakeSink{})

	sent := make(chan uint64, 10)
	stop := pollDrops(sess, w, func(n uint64) { sent <- n }, time.Millisecond)
	defer stop()

	select {
	case n := <-sent:
		t.Fatalf("want no send while the count stays at zero, got %d", n)
	case <-time.After(20 * time.Millisecond):
	}

	mu.Lock()
	total = 7
	mu.Unlock()

	select {
	case n := <-sent:
		if n != 7 {
			t.Errorf("send = %d, want 7", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for send after the count changed")
	}
}

func TestPollDrops_SuppressesWhenUnchanged(t *testing.T) {
	sess := &fakeBPF{drops: drops.Counts{Ringbuf: 3}}
	w := newSSLWatcher(&fakeSink{})

	sent := make(chan uint64, 10)
	stop := pollDrops(sess, w, func(n uint64) { sent <- n }, time.Millisecond)

	select {
	case n := <-sent:
		if n != 3 {
			t.Errorf("send = %d, want 3", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for the initial send")
	}

	time.Sleep(20 * time.Millisecond) // let several ticks pass with an unchanged count
	stop()

	select {
	case n := <-sent:
		t.Errorf("want no further sends once the count stops changing, got %d", n)
	default:
	}
}

func TestPollDrops_StopJoinsCleanly(t *testing.T) {
	sess := &fakeBPF{}
	w := newSSLWatcher(&fakeSink{})
	stop := pollDrops(sess, w, func(uint64) {}, time.Millisecond)

	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not return promptly")
	}
}

// A second call to stop must not panic on a double-close of the done channel.
func TestPollDrops_StopIsIdempotent(t *testing.T) {
	sess := &fakeBPF{}
	w := newSSLWatcher(&fakeSink{})
	stop := pollDrops(sess, w, func(uint64) {}, time.Millisecond)
	stop()
	stop()
}
