package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	"golang.org/x/term"

	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/output/stdout"
	"github.com/shinagawa-web/tinytap/internal/output/tui"
)

// appConfig holds the parsed CLI flags.
type appConfig struct {
	outputMode string
	verbose    bool
}

// parseFlags parses args using a fresh FlagSet so it is safe to call from tests.
func parseFlags(args []string) (appConfig, error) {
	fs := flag.NewFlagSet("tinytap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outputMode := fs.String("output", "auto", "output mode: auto (TUI on a terminal), stdout (line stream), tui")
	verbose := fs.Bool("v", false, "verbose: hang request/response headers under each exchange (stdout only)")
	fs.BoolVar(verbose, "verbose", false, "alias for -v")
	if err := fs.Parse(args); err != nil {
		return appConfig{}, err
	}
	switch *outputMode {
	case "auto", "stdout", "tui":
	default:
		return appConfig{}, fmt.Errorf("invalid --output %q: want auto, stdout, or tui", *outputMode)
	}
	return appConfig{outputMode: *outputMode, verbose: *verbose}, nil
}

// bpfSession abstracts *loader.Tinytap so run() can be tested without eBPF.
type bpfSession interface {
	Close() error
	reader() ringbufCloser
}

// tuiSink is implemented by *tui.Sink.
type tuiSink interface {
	output.Sink
	Run() error
	Quit()
}

// tuiRunner abstracts the Run/Quit lifecycle for runCapturePipeline.
type tuiRunner interface {
	Run() error
	Quit()
}

// Injected callables — replaced in tests to avoid eBPF and real terminals.
var (
	loadBPF      func(pid uint32) (bpfSession, error) // set by bpf.go init()
	isTerminalFn = term.IsTerminal
	getSizeFn    = term.GetSize
	newTUISink   func(w, h int) tuiSink      = defaultNewTUISink
	newStdoutSink func(verbose bool) output.Sink = defaultNewStdoutSink
	doRunStdout  func(ringbufCloser, bool)    = runStdout
	doRunTUI     func(ringbufCloser, int, int) = runTUI
)

func defaultNewTUISink(w, h int) tuiSink          { return tui.New(w, h) }
func defaultNewStdoutSink(verbose bool) output.Sink { return stdout.New(verbose) }

func run() error {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		return err
	}

	decision, w, h := decideOutput(cfg.outputMode, isTerminalFn, getSizeFn)
	if decision == outputExit {
		return errSilentExit
	}

	tt, err := loadBPF(uint32(os.Getpid()))
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer func() {
		if err := tt.Close(); err != nil {
			log.Printf("teardown: %v", err)
		}
	}()

	if decision == outputTUI {
		doRunTUI(tt.reader(), w, h)
	} else {
		doRunStdout(tt.reader(), cfg.verbose)
	}
	return nil
}

// closeOnInterrupt closes rd when a signal arrives on stop.
func closeOnInterrupt(rd io.Closer, stop <-chan os.Signal) {
	go func() {
		<-stop
		if err := rd.Close(); err != nil {
			log.Printf("close reader: %v", err)
		}
	}()
}

func runStdout(rd ringbufCloser, verbose bool) {
	sink := newStdoutSink(verbose)
	defer closeSink(sink)
	log.Println("tinytap running — watching accept4/read/write/close/recvfrom/sendto/recvmsg/sendmsg. Press Ctrl-C to stop.")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	closeOnInterrupt(rd, stop)
	capture(rd, sink)
}

// runCapturePipeline feeds capture into sink while the TUI runs. It closes rd
// after the TUI exits, then waits for capture to finish.
func runCapturePipeline(rd ringbufCloser, sink output.Sink, ui tuiRunner) error {
	done := make(chan struct{})
	go func() {
		capture(rd, sink)
		close(done)
		ui.Quit()
	}()
	runErr := ui.Run()
	if err := rd.Close(); err != nil {
		log.Printf("close reader: %v", err)
	}
	<-done
	return runErr
}

func runTUI(rd ringbufCloser, width, height int) {
	sink := newTUISink(width, height)
	defer closeSink(sink)

	// Mute logging for the TUI session so stray lines can't corrupt the alt-screen.
	prev := log.Writer()
	log.SetOutput(io.Discard)

	runErr := runCapturePipeline(rd, sink, sink)

	log.SetOutput(prev)
	if runErr != nil {
		log.Printf("tui: %v", runErr)
	}
}

func closeSink(sink output.Sink) {
	if err := sink.Close(); err != nil {
		log.Printf("sink close: %v", err)
	}
}
