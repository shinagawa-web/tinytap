// Command tinytap attaches the BPF program, drains its ringbuf, parses
// the per-syscall events into HTTP messages, pairs requests with
// responses, and feeds the result to an output sink.
//
// Everything beyond this file is in internal/: the BPF lifecycle in
// internal/loader, the event struct + decode in internal/events,
// per-protocol parsing under internal/protocols/, and output rendering
// under internal/output/. main.go only wires them together and decides
// which sink drains the pipeline.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	"golang.org/x/term"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/output/stdout"
	"github.com/shinagawa-web/tinytap/internal/output/tui"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// The TUI assumes a terminal at least this large; below it the layout breaks,
// so both auto and an explicit --output tui decline to start (see #32).
const (
	minCols = 120
	minRows = 24
)

func main() {
	outputMode := flag.String("output", "auto", "output mode: auto (TUI on a terminal), stdout (raw line stream), tui")
	flag.Parse()

	switch *outputMode {
	case "auto", "stdout", "tui":
	default:
		log.Fatalf("invalid --output %q: want auto, stdout, or tui", *outputMode)
	}

	// Decide before attaching BPF: the no-terminal / too-small paths exit
	// here, so nothing is loaded that would need tearing down.
	decision, w, h := decideOutput(*outputMode)
	if decision == outputExit {
		os.Exit(1)
	}

	tt, err := loader.Load(uint32(os.Getpid()))
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer func() {
		if err := tt.Close(); err != nil {
			log.Printf("teardown: %v", err)
		}
	}()

	if decision == outputTUI {
		runTUI(tt, w, h)
	} else {
		runStdout(tt)
	}
}

type outputChoice int

const (
	outputTUI outputChoice = iota
	outputStdout
	outputExit
)

// decideOutput picks the output backend. The TUI is the default; the raw
// stdout line stream is opt-in via --output stdout only. So auto and tui
// never silently stream — when the terminal can't host the TUI they print
// guidance and bail (outputExit), pointing at --output stdout for piping or
// logging. It returns the terminal size to seed the TUI's first frame.
func decideOutput(mode string) (choice outputChoice, width, height int) {
	if mode == "stdout" {
		return outputStdout, 0, 0
	}
	// Both streams must be terminals: stdout to render the alt-screen, stdin
	// to receive keystrokes (q / Ctrl-C). A piped stdin would draw a TUI that
	// can never be quit; a piped stdout has nowhere to render.
	if !term.IsTerminal(int(os.Stdout.Fd())) || !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "tinytap needs an interactive terminal for the TUI.")
		fmt.Fprintln(os.Stderr, "Run it in a terminal, or use --output stdout to stream lines to a pipe or file.")
		return outputExit, 0, 0
	}
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not determine terminal size — use --output stdout to stream lines instead.")
		return outputExit, 0, 0
	}
	// The minimum size is a hard floor for the TUI: below it the layout
	// breaks (visibleRows can hit 0, the panel can't keep a row navigable),
	// so both auto and an explicit --output tui bail rather than render a
	// broken frame. --output stdout is the escape hatch for any size.
	if w < minCols || h < minRows {
		fmt.Fprintf(os.Stderr, "Terminal too small for the TUI — need at least %dx%d, got %dx%d.\n", minCols, minRows, w, h)
		fmt.Fprintln(os.Stderr, "Resize the terminal and retry, or run with --output stdout.")
		return outputExit, 0, 0
	}
	return outputTUI, w, h
}

// runStdout drives the v0.1.0 line format. Ctrl-C is delivered as a signal
// (the terminal stays in cooked mode) and closes the ringbuf reader, which
// unblocks capture.
func runStdout(tt *loader.Tinytap) {
	sink := stdout.New()
	defer closeSink(sink)

	log.Println("tinytap running — watching accept4/read/write/close/recvfrom/sendto/recvmsg/sendmsg. Press Ctrl-C to stop.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		tt.Reader.Close()
	}()

	capture(tt, sink)
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
		capture(tt, sink)
		close(done)
		sink.Quit()
	}()

	runErr := sink.Run()
	tt.Reader.Close()
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

// capture drains the ringbuf, decodes each event, feeds the HTTP parser and
// pairer, and drives the sink in wire order: OnEvent for the raw event, then
// OnMessage / OnPaired for whatever that event completed. It returns when the
// reader is closed (Ctrl-C path) or hits an unrecoverable read error.
func capture(tt *loader.Tinytap, sink output.Sink) {
	parser := http.NewParser()
	pairer := http.NewPairer()

	var e events.Event
	for {
		rec, err := tt.Reader.Read()
		if err != nil {
			break
		}
		if err := events.Decode(rec.RawSample, &e); err != nil {
			log.Printf("parse event: %v", err)
			continue
		}
		sink.OnEvent(&e)

		for _, m := range parser.Feed(&e) {
			sink.OnMessage(m)
			if pe, ok := pairer.Push(m); ok {
				sink.OnPaired(pe)
			}
		}
		if e.Syscall == events.SyscallClose {
			parser.Close(e.Pid, e.Fd)
			pairer.Close(e.Pid, e.Fd)
		}
	}
}
