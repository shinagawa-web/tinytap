package main

import (
	"log"
	"sync"
	"time"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
	"github.com/shinagawa-web/tinytap/internal/tls"
)

type sslFdLookup interface {
	Lookup(pid uint32, ssl uint64) (int32, bool)
	Delete(pid uint32, ssl uint64)
}

func captureTLS(rd ringbufReader, fdProbe sslFdLookup, sink output.Sink, parser *http.Parser, pairer *http.Pairer) {
	captureTLSWithOptions(rd, fdProbe, sink, parser, pairer, sweepInterval, pendingTimeout)
}

func captureTLSWithOptions(rd ringbufReader, fdProbe sslFdLookup, sink output.Sink, parser *http.Parser, pairer *http.Pairer, interval, timeout time.Duration) {
	var mu sync.Mutex

	done := make(chan struct{})
	var sweepDone sync.WaitGroup
	sweepDone.Add(1)
	defer func() {
		close(done)
		sweepDone.Wait()
	}()

	go func() {
		defer sweepDone.Done()
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

	var e events.SSLEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			return
		}
		if err := events.DecodeSSL(rec.RawSample, &e); err != nil {
			log.Printf("parse ssl event: %v", err)
			continue
		}

		fd, ok := fdProbe.Lookup(e.Pid, e.SSL)
		if e.Op == events.SSLOpFree {
			fdProbe.Delete(e.Pid, e.SSL)
		}

		mu.Lock()
		switch {
		case e.Op == events.SSLOpFree && ok:
			parser.Close(e.Pid, fd)
			for _, ab := range pairer.Close(e.Pid, fd, e.TsNs) {
				sink.OnPaired(ab)
			}
		case e.Op == events.SSLOpFree:
			parser.CloseSSL(e.Pid, e.SSL)
			for _, ab := range pairer.CloseSSL(e.Pid, e.SSL, e.TsNs) {
				sink.OnPaired(ab)
			}
		case ok:
			if ev, okConv := tls.FromSSL(&e, fd); okConv {
				sink.OnEvent(&ev)
				for _, m := range parser.Feed(&ev) {
					sink.OnMessage(m)
					if pe, okPush := pairer.Push(m); okPush {
						sink.OnPaired(pe)
					}
				}
			}
		default:
			for _, m := range parser.FeedSSL(&e) {
				sink.OnMessage(m)
				if pe, okPush := pairer.Push(m); okPush {
					sink.OnPaired(pe)
				}
			}
		}
		mu.Unlock()
	}
}
