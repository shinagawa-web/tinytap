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
	"log"
	"os"
	"os/signal"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/output/stdout"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

func main() {
	noTUI := flag.Bool("no-tui", false, "disable the TUI and print v0.1.0-style lines to stdout")
	flag.Parse()

	tt, err := loader.Load(uint32(os.Getpid()))
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer func() {
		if err := tt.Close(); err != nil {
			log.Printf("teardown: %v", err)
		}
	}()

	// Sink selection. The TUI sink and its TTY/size gate arrive in the next
	// v0.2.0 child (#38); until then every path renders to stdout, so
	// --no-tui is accepted but has no visible effect yet.
	var sink output.Sink = stdout.New()
	_ = noTUI // TODO(#38): drive the bubbletea TUI sink here unless --no-tui.
	defer func() {
		if err := sink.Close(); err != nil {
			log.Printf("sink close: %v", err)
		}
	}()

	log.Println("tinytap running — watching accept4/read/write/close/recvfrom/sendto/recvmsg/sendmsg. Press Ctrl-C to stop.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		tt.Reader.Close()
	}()

	capture(tt, sink)
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
