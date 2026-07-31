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

// sslFdLookup is the subset of *loader.SSLFdProbe captureTLS needs —
// narrowed to an interface so tests can inject a fake instead of a real
// eBPF-backed probe.
type sslFdLookup interface {
	Lookup(pid uint32, ssl uint64) (int32, bool)
}

// captureTLS drains a single pid's SSL_write/SSL_read/SSL_free uprobe
// ringbuf (#146/#173) into its own dedicated Parser/Pairer, mirroring
// capture's plaintext loop. It never shares a Parser/Pairer with capture's
// own: tls.FromSSL's doc explains why mixing ciphertext syscall bytes and
// uprobe-decrypted bytes under the same (pid, fd) key would corrupt the
// stream. sink must be safe for concurrent use — sslWatcher, the only
// caller, guards its own sink calls with a mutex shared across every
// captureTLS goroutine and the plaintext capture loop (see tlswatch.go).
//
// fdProbe.Lookup failing means the connection is fd-less (e.g. curl, which
// never calls SSL_set_fd — #167): those payload events go through
// Parser.FeedSSL's SSL*-keyed stream (#179) instead of the fd-keyed
// Parser.Feed, and their SSL_free events evict via Parser.CloseSSL +
// Pairer.CloseSSL rather than the fd-keyed Close pair.
//
// parser and pairer are caller-constructed (mirroring fdProbe/sink) rather
// than built internally, so each pid's captureTLS goroutine gets its own
// dedicated pair (never capture's plaintext ones — see above) while still
// staying easy to drive from tests without needing a live ringbuf.
//
// Returns when rd's underlying ringbuf is closed (pid exited, or tinytap
// shutdown — see sslWatcher.Close) or hits an unrecoverable read error.
func captureTLS(rd ringbufReader, fdProbe sslFdLookup, sink output.Sink, parser *http.Parser, pairer *http.Pairer) {
	captureTLSWithOptions(rd, fdProbe, sink, parser, pairer, sweepInterval, pendingTimeout)
}

func captureTLSWithOptions(rd ringbufReader, fdProbe sslFdLookup, sink output.Sink, parser *http.Parser, pairer *http.Pairer, interval, timeout time.Duration) {
	var mu sync.Mutex

	done := make(chan struct{})
	var sweepDone sync.WaitGroup
	sweepDone.Add(1)
	// close(done) only signals the sweeper to stop on its next select
	// iteration — without waiting for it to actually exit, the sweeper could
	// still be mid-OnPaired when this function returns (see capture.go's
	// identical fix for the same pattern).
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
			// fd-less payload event (curl, #167): fed through the SSL*-keyed
			// stream (#179) instead of dropped.
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
