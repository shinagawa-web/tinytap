package main

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// marshalSSLEvent builds a wire-format ssl_event byte slice matching the C
// struct's explicit layout (bpf/tinytap_uprobe.bpf.c), including the 4-byte
// alignment pad between payload_len and comm that events.SSLEvent has no Go
// field for — mirrors internal/events' own (unexported) makeSSLRaw helper.
func marshalSSLEvent(t *testing.T, e events.SSLEvent) []byte {
	t.Helper()
	const wireSize = 56 + events.MaxSSLPayload
	raw := make([]byte, wireSize)
	binary.LittleEndian.PutUint64(raw[0:8], e.TsNs)
	binary.LittleEndian.PutUint32(raw[8:12], e.Pid)
	binary.LittleEndian.PutUint32(raw[12:16], e.Tid)
	binary.LittleEndian.PutUint64(raw[16:24], e.SSL)
	binary.LittleEndian.PutUint32(raw[24:28], e.Op)
	binary.LittleEndian.PutUint32(raw[28:32], e.Len)
	binary.LittleEndian.PutUint32(raw[32:36], e.PayloadLen)
	copy(raw[40:56], e.Comm[:])
	copy(raw[56:wireSize], e.Payload[:])
	return raw
}

// sslWriteEvent builds an SSLOpWrite event carrying payload as its
// plaintext, with Len/PayloadLen both set to len(payload) (no truncation).
func sslWriteEvent(pid, tid uint32, ssl uint64, payload []byte) events.SSLEvent {
	e := events.SSLEvent{Pid: pid, Tid: tid, SSL: ssl, Op: events.SSLOpWrite}
	n := copy(e.Payload[:], payload)
	e.Len = uint32(n)
	e.PayloadLen = uint32(n)
	return e
}

func sslReadEvent(pid, tid uint32, ssl uint64, payload []byte) events.SSLEvent {
	e := sslWriteEvent(pid, tid, ssl, payload)
	e.Op = events.SSLOpRead
	return e
}

// fakeSSLFdLookup implements sslFdLookup with a static (pid, ssl) -> fd map.
type fakeSSLFdLookup map[[2]uint64]int32

func (f fakeSSLFdLookup) Lookup(pid uint32, ssl uint64) (int32, bool) {
	fd, ok := f[[2]uint64{uint64(pid), ssl}]
	return fd, ok
}

func lookupKey(pid uint32, ssl uint64) [2]uint64 { return [2]uint64{uint64(pid), ssl} }

// newTLSTestPipeline builds a fresh Parser/Pairer pair, the same shape
// sslWatcher.maybeAttach constructs for each pid's captureTLS goroutine.
func newTLSTestPipeline() (*http.Parser, *http.Pairer) {
	return http.NewParser(), http.NewPairer()
}

func TestCaptureTLS_ReaderErrorImmediately(t *testing.T) {
	rd := &fakeReader{}
	sink := &fakeSink{}
	parser, pairer := newTLSTestPipeline()
	captureTLS(rd, fakeSSLFdLookup{}, sink, parser, pairer)
	if sink.eventCount != 0 {
		t.Errorf("want 0 events, got %d", sink.eventCount)
	}
}

func TestCaptureTLS_MalformedBytes(t *testing.T) {
	rd := &fakeReader{records: []ringbuf.Record{{RawSample: []byte{0x01, 0x02}}}}
	sink := &fakeSink{}
	parser, pairer := newTLSTestPipeline()
	captureTLS(rd, fakeSSLFdLookup{}, sink, parser, pairer)
	if sink.eventCount != 0 {
		t.Errorf("want 0 events on decode error, got %d", sink.eventCount)
	}
}

// TestCaptureTLS_WriteThenReadPairsWithResolvedFd is the concrete end-to-end
// proof that fd-resolvable TLS traffic (nginx, Python — see #167) reassembles
// and pairs through the existing HTTP parser/pairer exactly like plaintext
// traffic does, once tls.FromSSL bridges the two event shapes (#148).
func TestCaptureTLS_WriteThenReadPairsWithResolvedFd(t *testing.T) {
	const pid, ssl, fd = uint32(1), uint64(0xabc), int32(3)
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: marshalSSLEvent(t, sslWriteEvent(pid, pid, ssl, req))},
			{RawSample: marshalSSLEvent(t, sslReadEvent(pid, pid, ssl, resp))},
		},
	}
	fdProbe := fakeSSLFdLookup{lookupKey(pid, ssl): fd}
	sink := &fakeSink{}
	parser, pairer := newTLSTestPipeline()
	captureTLS(rd, fdProbe, sink, parser, pairer)

	if sink.eventCount != 2 {
		t.Errorf("want 2 raw events, got %d", sink.eventCount)
	}
	if sink.messageCount != 2 {
		t.Errorf("want 2 messages, got %d", sink.messageCount)
	}
	if sink.pairedCount != 1 {
		t.Errorf("want 1 paired event, got %d", sink.pairedCount)
	}
}

// TestCaptureTLS_FdLessTrafficDropped documents today's known gap (#149's
// flag on #171): payload events for a connection whose fd never resolved
// (curl, which never calls SSL_set_fd — #167) are dropped rather than
// guessed, since the parser has no SSL*-keyed stream to feed them into yet.
func TestCaptureTLS_FdLessTrafficDropped(t *testing.T) {
	const pid, ssl = uint32(1), uint64(0xdef)
	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: marshalSSLEvent(t, sslWriteEvent(pid, pid, ssl, []byte("GET / HTTP/1.1\r\n\r\n")))},
		},
	}
	sink := &fakeSink{}
	parser, pairer := newTLSTestPipeline()
	captureTLS(rd, fakeSSLFdLookup{}, sink, parser, pairer) // empty map: Lookup always misses

	if sink.eventCount != 0 || sink.messageCount != 0 || sink.pairedCount != 0 {
		t.Errorf("want fd-less payload dropped silently, got events=%d messages=%d paired=%d",
			sink.eventCount, sink.messageCount, sink.pairedCount)
	}
}

// TestCaptureTLS_SSLFreeEvictsPendingRequestWhenFdResolved confirms SSL_free
// (#173) promptly evicts a pending request as ABANDONED via the ordinary
// fd-keyed Close/Pairer.Close path when the connection's fd is resolvable —
// mirroring capture's own close(2)-driven eviction for plaintext traffic.
func TestCaptureTLS_SSLFreeEvictsPendingRequestWhenFdResolved(t *testing.T) {
	const pid, ssl, fd = uint32(5), uint64(0x111), int32(9)
	req := []byte("GET /slow HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")

	freeEvent := events.SSLEvent{Pid: pid, Tid: pid, SSL: ssl, Op: events.SSLOpFree}
	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: marshalSSLEvent(t, sslWriteEvent(pid, pid, ssl, req))},
			{RawSample: marshalSSLEvent(t, freeEvent)},
		},
	}
	fdProbe := fakeSSLFdLookup{lookupKey(pid, ssl): fd}
	sink := &abandonedSink{}
	parser, pairer := newTLSTestPipeline()
	captureTLS(rd, fdProbe, sink, parser, pairer)

	if len(sink.paired) != 1 {
		t.Fatalf("want 1 paired (abandoned) event, got %d", len(sink.paired))
	}
	pe := sink.paired[0]
	if !pe.Abandoned {
		t.Error("PairedEvent.Abandoned must be true")
	}
	if pe.Method != "GET" || pe.Path != "/slow" {
		t.Errorf("method/path = %q %q, want GET /slow", pe.Method, pe.Path)
	}
}

// TestCaptureTLS_SSLFreeEvictsSSLFallbackWhenFdLess confirms SSL_free (#173)
// evicts a pending SSLFallback-keyed request via Pairer.CloseSSL when the
// connection's fd never resolved. Nothing in captureTLS's own event loop can
// produce an SSLFallback-pending Message yet (that needs the parser-level
// SSL*-keyed stream flagged on #149) — the pairer is seeded directly here to
// prove CloseSSL's wiring is correct and ready for the moment that lands.
func TestCaptureTLS_SSLFreeEvictsSSLFallbackWhenFdLess(t *testing.T) {
	const pid, ssl = uint32(6), uint64(0x222)
	parser, pairer := newTLSTestPipeline()
	pairer.Push(http.Message{Pid: pid, SSL: ssl, SSLFallback: true, IsRequest: true, TsNs: 1})

	freeEvent := events.SSLEvent{Pid: pid, Tid: pid, SSL: ssl, Op: events.SSLOpFree}
	rd := &fakeReader{records: []ringbuf.Record{{RawSample: marshalSSLEvent(t, freeEvent)}}}
	sink := &abandonedSink{}
	captureTLS(rd, fakeSSLFdLookup{}, sink, parser, pairer) // empty map: fd never resolves

	if len(sink.paired) != 1 {
		t.Fatalf("want 1 paired (abandoned) event, got %d", len(sink.paired))
	}
	pe := sink.paired[0]
	if !pe.Abandoned || !pe.SSLFallback || pe.SSL != ssl {
		t.Errorf("want Abandoned=true SSLFallback=true SSL=%#x, got Abandoned=%v SSLFallback=%v SSL=%#x",
			ssl, pe.Abandoned, pe.SSLFallback, pe.SSL)
	}
}

// TestCaptureTLS_SweepEmitsAbandoned mirrors capture_test.go's
// TestCapture_SweepEmitsAbandoned: a pending fd-resolved request is evicted
// by the periodic sweeper (not Close/CloseSSL) once it outlives timeout,
// covering captureTLSWithOptions' own sweep goroutine.
func TestCaptureTLS_SweepEmitsAbandoned(t *testing.T) {
	const pid, ssl, fd = uint32(9), uint64(0x333), int32(4)
	req := []byte("GET /hang HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")

	rd := &slowReader{
		records: []ringbuf.Record{
			{RawSample: marshalSSLEvent(t, sslWriteEvent(pid, pid, ssl, req))},
		},
		delay: 20 * time.Millisecond, // keep captureTLS alive long enough for sweep
	}
	sink := &abandonedSink{}
	parser, pairer := newTLSTestPipeline()
	captureTLSWithOptions(rd, fakeSSLFdLookup{lookupKey(pid, ssl): fd}, sink, parser, pairer, 1*time.Millisecond, 1*time.Millisecond)

	var abandoned []http.PairedEvent
	for _, pe := range sink.paired {
		if pe.Abandoned {
			abandoned = append(abandoned, pe)
		}
	}
	if len(abandoned) == 0 {
		t.Fatal("want at least 1 abandoned event from sweeper, got 0")
	}
	if abandoned[0].AbandonReason != http.AbandonReasonTimeout {
		t.Errorf("AbandonReason = %q, want %q", abandoned[0].AbandonReason, http.AbandonReasonTimeout)
	}
}

func TestCaptureTLS_TruncatedSSLOpIsDropped(t *testing.T) {
	// An SSL op value outside SSLOpWrite/SSLOpRead/SSLOpFree (e.g. a decode
	// mismatch) must not panic and must produce no output.
	const pid, ssl = uint32(1), uint64(1)
	e := events.SSLEvent{Pid: pid, Tid: pid, SSL: ssl, Op: 99}
	rd := &fakeReader{records: []ringbuf.Record{{RawSample: marshalSSLEvent(t, e)}}}
	sink := &fakeSink{}
	parser, pairer := newTLSTestPipeline()
	captureTLS(rd, fakeSSLFdLookup{lookupKey(pid, ssl): 3}, sink, parser, pairer)

	if sink.eventCount != 0 {
		t.Errorf("want 0 events for an unrecognized op, got %d", sink.eventCount)
	}
}
