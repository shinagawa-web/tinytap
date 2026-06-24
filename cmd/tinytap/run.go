package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	"golang.org/x/term"

	"github.com/shinagawa-web/tinytap/internal/loader"
	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/output/stdout"
	"github.com/shinagawa-web/tinytap/internal/output/tui"
)

func run() error {
	outputMode := flag.String("output", "auto", "output mode: auto (TUI on a terminal), stdout (line stream), tui")
	verbose := flag.Bool("v", false, "verbose: hang request/response headers under each exchange (stdout only)")
	flag.BoolVar(verbose, "verbose", false, "alias for -v")
	flag.Parse()

	switch *outputMode {
	case "auto", "stdout", "tui":
	default:
		return fmt.Errorf("invalid --output %q: want auto, stdout, or tui", *outputMode)
	}

	// Decide before attaching BPF: the no-terminal / too-small paths exit
	// here, so nothing is loaded that would need tearing down.
	decision, w, h := decideOutput(*outputMode, term.IsTerminal, term.GetSize)
	if decision == outputExit {
		return errSilentExit
	}

	tt, err := loader.Load(uint32(os.Getpid()))
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer func() {
		if err := tt.Close(); err != nil {
			log.Printf("teardown: %v", err)
		}
	}()

	if decision == outputTUI {
		runTUI(tt, w, h)
	} else {
		runStdout(tt, *verbose)
	}
	return nil
}

// runStdout drives the line-oriented exchange log. Ctrl-C is delivered as a
// signal (the terminal stays in cooked mode) and closes the ringbuf reader,
// which unblocks capture.
func runStdout(tt *loader.Tinytap, verbose bool) {
	sink := stdout.New(verbose)
	defer closeSink(sink)

	log.Println("tinytap running — watching accept4/read/write/close/recvfrom/sendto/recvmsg/sendmsg. Press Ctrl-C to stop.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		if err := tt.Reader.Close(); err != nil {
			log.Printf("close reader: %v", err)
		}
	}()

	capture(tt.Reader, sink)
}

// runTUI drives the Bubble Tea table. Capture runs on a goroutine feeding the
// UI via Program.Send while Run holds the main goroutine. Two quit paths
// converge here: the user presses q/Ctrl-C (Run returns, we close the reader
// to stop capture), or capture dies on its own (we Quit the UI). Bubble Tea
// owns the terminal and translates Ctrl-C itself, so no signal handler is
// installed; log output is muted for the session so stray lines (e.g. a
// decode error) can't corrupt the alt-screen.
func runTUI(tt *loader.Tinytap, width, height int) {
	sink := tui.New(width, height)
	defer closeSink(sink)

	// Mute logging before capture starts and keep it muted until capture has
	// fully stopped, so a stray line (e.g. a decode error) can never land on
	// the alt-screen — not even during startup or teardown.
	prev := log.Writer()
	log.SetOutput(io.Discard)

	done := make(chan struct{})
	go func() {
		capture(tt.Reader, sink)
		close(done)
		sink.Quit()
	}()

	runErr := sink.Run()
	if err := tt.Reader.Close(); err != nil {
		log.Printf("close reader: %v", err)
	}
	<-done

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
