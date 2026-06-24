package main

import (
	"io"
	"log"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/proc"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

type ringbufReader interface {
	Read() (ringbuf.Record, error)
}

type ringbufCloser interface {
	ringbufReader
	io.Closer
}

// capture drains the ringbuf, decodes each event, feeds the HTTP parser and
// pairer, and drives the sink in wire order: OnEvent for the raw event, then
// OnMessage / OnPaired for whatever that event completed. It returns when the
// reader is closed (Ctrl-C path) or hits an unrecoverable read error.
func capture(rd ringbufReader, sink output.Sink) {
	parser := http.NewParserWithResolve(func(pid uint32) string {
		return proc.LookupCmdline("", pid)
	})
	pairer := http.NewPairer()

	var e events.Event
	for {
		rec, err := rd.Read()
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
