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
// so auto mode falls back to the stdout sink with a notice (see #32).
const (
	minCols = 120
	minRows = 24
)

func main() {
	outputMode := flag.String("output", "auto", "output mode: auto, stdout, tui")
	flag.Parse()

	switch *outputMode {
	case "auto", "stdout", "tui":
	default:
		log.Fatalf("invalid --output %q: want auto, stdout, or tui", *outputMode)
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

	// Sink selection. The TUI is the default on an interactive terminal;
	// stdout is the fallback (and the forced choice for --output stdout).
	if w, h, ok := tuiViable(*outputMode); ok {
		runTUI(tt, w, h)
	} else {
		runStdout(tt)
	}
}

// tuiViable reports whether the TUI can run under the given output mode,
// returning the terminal size to seed the first frame. It prints a fallback
// notice when the user asked for a TUI but the terminal can't host one.
func tuiViable(mode string) (width, height int, ok bool) {
	if mode == "stdout" {
		return 0, 0, false
	}
	// Both streams must be terminals: stdout to render the alt-screen, stdin
	// to receive keystrokes (q / Ctrl-C). With stdin piped the TUI would draw
	// but never take input, so it could not be quit interactively.
	fd := int(os.Stdout.Fd())
	if !term.IsTerminal(fd) || !term.IsTerminal(int(os.Stdin.Fd())) {
		// auto silently falls back so `tinytap > log.txt` works unflagged;
		// an explicit --output tui says why nothing interactive appeared.
		if mode == "tui" {
			log.Println("stdin and stdout must both be terminals — falling back to stdout")
		}
		return 0, 0, false
	}
	w, h, err := term.GetSize(fd)
	if err != nil {
		return 0, 0, false
	}
	// auto enforces the minimum size; an explicit --output tui is an override
	// that takes the cramped layout the user asked for.
	if mode == "auto" && (w < minCols || h < minRows) {
		log.Printf("Terminal too narrow — need at least %d cols x %d rows; got %dx%d — falling back to stdout", minCols, minRows, w, h)
		return 0, 0, false
	}
	return w, h, true
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
