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

// tlsStreams holds the HTTP parsing state shared by every pid attached to
// one libssl inode (#327): one ringbuf reader feeds one Parser/Pairer pair
// for all of them, so access must be serialized under mu.
type tlsStreams struct {
	mu     sync.Mutex
	parser *http.Parser
	pairer *http.Pairer
}

func newTLSStreams() *tlsStreams {
	return &tlsStreams{
		parser: http.NewParserWithResolve(resolveComm),
		pairer: http.NewPairer(),
	}
}

// closePid drops pid's parser state. Callers must not hold w.mu (or any lock
// also taken while processing an event) when calling this: the capture
// goroutine acquires st.mu and then, via sink.OnEvent, may re-enter the
// watcher and take w.mu — so w.mu -> st.mu is the only safe lock order.
func (s *tlsStreams) closePid(pid uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parser.ClosePid(pid)
}

func captureTLS(rd ringbufReader, fdProbe sslFdLookup, sink output.Sink, st *tlsStreams) {
	captureTLSWithOptions(rd, fdProbe, sink, st, sweepInterval, pendingTimeout)
}

func captureTLSWithOptions(rd ringbufReader, fdProbe sslFdLookup, sink output.Sink, st *tlsStreams, interval, timeout time.Duration) {
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
				st.mu.Lock()
				for _, ab := range st.pairer.Sweep(timeout) {
					sink.OnPaired(ab)
				}
				st.mu.Unlock()
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

		st.mu.Lock()
		switch {
		case e.Op == events.SSLOpFree && ok:
			st.parser.Close(e.Pid, fd)
			for _, ab := range st.pairer.Close(e.Pid, fd, e.TsNs) {
				sink.OnPaired(ab)
			}
		case e.Op == events.SSLOpFree:
			st.parser.CloseSSL(e.Pid, e.SSL)
			for _, ab := range st.pairer.CloseSSL(e.Pid, e.SSL, e.TsNs) {
				sink.OnPaired(ab)
			}
		case ok:
			if ev, okConv := tls.FromSSL(&e, fd); okConv {
				sink.OnEvent(&ev)
				for _, m := range st.parser.Feed(&ev) {
					sink.OnMessage(m)
					if pe, okPush := st.pairer.Push(m); okPush {
						sink.OnPaired(pe)
					}
				}
			}
		default:
			for _, m := range st.parser.FeedSSL(&e) {
				sink.OnMessage(m)
				if pe, okPush := st.pairer.Push(m); okPush {
					sink.OnPaired(pe)
				}
			}
		}
		st.mu.Unlock()
	}
}
