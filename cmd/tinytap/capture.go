package main

import (
	"io"
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/proc"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

const (
	sweepInterval  = 10 * time.Second
	pendingTimeout = 30 * time.Second
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
//
// A background sweeper ticks every sweepInterval and evicts pending requests
// older than pendingTimeout, emitting abandoned PairedEvents for each.
func capture(rd ringbufReader, sink output.Sink) {
	captureWithOptions(rd, sink, sweepInterval, pendingTimeout)
}

func captureWithOptions(rd ringbufReader, sink output.Sink, interval, timeout time.Duration) {
	parser := http.NewParserWithResolve(func(pid uint32) string {
		return proc.LookupCmdline("", pid)
	})
	pairer := http.NewPairer()

	var mu sync.Mutex

	done := make(chan struct{})
	defer close(done)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				for _, ab := range pairer.Sweep(timeout) {
					sink.OnPaired(ab)
				}
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()

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
		mu.Lock()
		sink.OnEvent(&e)

		for _, m := range parser.Feed(&e) {
			sink.OnMessage(m)
			if pe, ok := pairer.Push(m); ok {
				sink.OnPaired(pe)
			}
		}
		if e.Syscall == events.SyscallClose {
			parser.Close(e.Pid, e.Fd)
			for _, ab := range pairer.Close(e.Pid, e.Fd, e.TsNs) {
				sink.OnPaired(ab)
			}
		}
		mu.Unlock()
	}
}
