package main

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/output"
	httpproto "github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// fakeBPF implements bpfSession for testing.
type fakeBPF struct {
	rd       ringbufCloser
	closeErr error
}

func (f *fakeBPF) reader() ringbufCloser { return f.rd }
func (f *fakeBPF) Close() error          { return f.closeErr }

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
}

func (f *fakeTUISink) OnEvent(*events.Event)          {}
func (f *fakeTUISink) OnMessage(httpproto.Message)    {}
func (f *fakeTUISink) OnPaired(httpproto.PairedEvent) {}
func (f *fakeTUISink) Close() error                   { return nil }
func (f *fakeTUISink) Run() error                     { return f.runErr }
func (f *fakeTUISink) Quit()                          { f.quit = true }

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

// --- defaultNewTUISink / defaultNewStdoutSink ---

func TestDefaultNewTUISink(t *testing.T) {
	s := defaultNewTUISink(120, 24)
	if s == nil {
		t.Error("want non-nil tuiSink")
	}
}

func TestDefaultNewStdoutSink(t *testing.T) {
	s := defaultNewStdoutSink(false)
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
	if cfg.outputMode != "auto" {
		t.Errorf("want auto, got %s", cfg.outputMode)
	}
	if cfg.verbose {
		t.Error("want verbose=false")
	}
}

func TestParseFlags_ValidModes(t *testing.T) {
	for _, mode := range []string{"auto", "stdout", "tui"} {
		cfg, err := parseFlags([]string{"--output", mode})
		if err != nil {
			t.Errorf("mode %s: %v", mode, err)
		}
		if cfg.outputMode != mode {
			t.Errorf("want %s, got %s", mode, cfg.outputMode)
		}
	}
}

func TestParseFlags_InvalidMode(t *testing.T) {
	_, err := parseFlags([]string{"--output", "invalid"})
	if err == nil {
		t.Error("want error for invalid mode")
	}
}

func TestParseFlags_VerboseShort(t *testing.T) {
	cfg, err := parseFlags([]string{"-v"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.verbose {
		t.Error("want verbose=true")
	}
}

func TestParseFlags_VerboseLong(t *testing.T) {
	cfg, err := parseFlags([]string{"--verbose"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.verbose {
		t.Error("want verbose=true")
	}
}

func TestParseFlags_UnknownFlag(t *testing.T) {
	_, err := parseFlags([]string{"--nonexistent"})
	if err == nil {
		t.Error("want error for unknown flag")
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

func TestRun_InvalidMode(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap", "--output", "bad"}
	defer func() { os.Args = old }()

	if err := run(); err == nil {
		t.Error("want error for invalid mode")
	}
}

func TestRun_OutputExit(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap"} // auto — no TTY in CI
	defer func() { os.Args = old }()

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
	os.Args = []string{"tinytap", "--output", "stdout"}
	defer func() { os.Args = old }()

	oldLoad := loadBPF
	loadBPF = func(uint32) (bpfSession, error) { return nil, errors.New("no eBPF") }
	defer func() { loadBPF = oldLoad }()

	if err := run(); err == nil {
		t.Error("want error from loadBPF")
	}
}

func TestRun_TeardownError(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap", "--output", "stdout"}
	defer func() { os.Args = old }()

	oldLoad := loadBPF
	loadBPF = func(uint32) (bpfSession, error) {
		return &fakeBPF{rd: newFakeRC(), closeErr: errors.New("teardown err")}, nil
	}
	defer func() { loadBPF = oldLoad }()

	oldRun := doRunStdout
	doRunStdout = func(ringbufCloser, bool) {}
	defer func() { doRunStdout = oldRun }()

	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func TestRun_RoutesToStdout(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap", "--output", "stdout"}
	defer func() { os.Args = old }()

	oldLoad := loadBPF
	loadBPF = func(uint32) (bpfSession, error) { return &fakeBPF{rd: newFakeRC()}, nil }
	defer func() { loadBPF = oldLoad }()

	called := false
	oldRun := doRunStdout
	doRunStdout = func(ringbufCloser, bool) { called = true }
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
	doRunTUI = func(ringbufCloser, int, int) { called = true }
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
	newStdoutSink = func(bool) output.Sink { return &fakeSink{} }
	defer func() { newStdoutSink = oldSink }()

	runStdout(rd, false)
}

func TestRunStdout_Verbose(t *testing.T) {
	rd := newFakeRC()

	oldSink := newStdoutSink
	newStdoutSink = func(bool) output.Sink { return &fakeSink{} }
	defer func() { newStdoutSink = oldSink }()

	runStdout(rd, true)
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

	runTUI(rd, 120, 24)
}

func TestRunTUI_LogsUIError(t *testing.T) {
	rd := newFakeRC()
	fakeTUI := &fakeTUISink{runErr: errors.New("tui failed")}

	oldNew := newTUISink
	newTUISink = func(int, int) tuiSink { return fakeTUI }
	defer func() { newTUISink = oldNew }()

	runTUI(rd, 120, 24)
}

// --- closeSink ---

func TestCloseSink_NoError(t *testing.T) {
	closeSink(&fakeSink{})
}

func TestCloseSink_WithError(t *testing.T) {
	closeSink(&fakeSink{closeErr: errors.New("close failed")})
}
