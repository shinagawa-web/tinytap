package main

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

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

type fakeSSLFdLookup map[[2]uint64]int32

func (f fakeSSLFdLookup) Lookup(pid uint32, ssl uint64) (int32, bool) {
	fd, ok := f[[2]uint64{uint64(pid), ssl}]
	return fd, ok
}

func (f fakeSSLFdLookup) Delete(pid uint32, ssl uint64) {
	delete(f, [2]uint64{uint64(pid), ssl})
}

func lookupKey(pid uint32, ssl uint64) [2]uint64 { return [2]uint64{uint64(pid), ssl} }

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

func TestCaptureTLS_FdLessTrafficParsedAndPaired(t *testing.T) {
	const pid, ssl = uint32(1), uint64(0xdef)
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: marshalSSLEvent(t, sslWriteEvent(pid, pid, ssl, req))},
			{RawSample: marshalSSLEvent(t, sslReadEvent(pid, pid, ssl, resp))},
		},
	}
	sink := &fakeSink{}
	parser, pairer := newTLSTestPipeline()
	captureTLS(rd, fakeSSLFdLookup{}, sink, parser, pairer)

	if sink.eventCount != 0 {
		t.Errorf("want 0 raw events for the fd-less path, got %d", sink.eventCount)
	}
	if sink.messageCount != 2 {
		t.Errorf("want 2 messages, got %d", sink.messageCount)
	}
	if sink.pairedCount != 1 {
		t.Errorf("want 1 paired event, got %d", sink.pairedCount)
	}
}

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

func TestCaptureTLS_SSLFreeEvictsSSLFallbackWhenFdLess(t *testing.T) {
	const pid, ssl = uint32(6), uint64(0x222)
	req := []byte("GET /slow HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")

	freeEvent := events.SSLEvent{Pid: pid, Tid: pid, SSL: ssl, Op: events.SSLOpFree}
	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: marshalSSLEvent(t, sslWriteEvent(pid, pid, ssl, req))},
			{RawSample: marshalSSLEvent(t, freeEvent)},
		},
	}
	sink := &abandonedSink{}
	parser, pairer := newTLSTestPipeline()
	captureTLS(rd, fakeSSLFdLookup{}, sink, parser, pairer)

	if len(sink.paired) != 1 {
		t.Fatalf("want 1 paired (abandoned) event, got %d", len(sink.paired))
	}
	pe := sink.paired[0]
	if !pe.Abandoned || !pe.SSLFallback || pe.SSL != ssl {
		t.Errorf("want Abandoned=true SSLFallback=true SSL=%#x, got Abandoned=%v SSLFallback=%v SSL=%#x",
			ssl, pe.Abandoned, pe.SSLFallback, pe.SSL)
	}
	if pe.Path != "/slow" {
		t.Errorf("Path = %q, want /slow", pe.Path)
	}
}

func TestCaptureTLS_SSLFreeDeletesFdMapEntry(t *testing.T) {
	const pid, ssl, fd = uint32(7), uint64(0x333), int32(3)

	freeEvent := events.SSLEvent{Pid: pid, Tid: pid, SSL: ssl, Op: events.SSLOpFree}
	rd := &fakeReader{records: []ringbuf.Record{{RawSample: marshalSSLEvent(t, freeEvent)}}}
	fdProbe := fakeSSLFdLookup{lookupKey(pid, ssl): fd}
	sink := &fakeSink{}
	parser, pairer := newTLSTestPipeline()
	captureTLS(rd, fdProbe, sink, parser, pairer)

	if _, ok := fdProbe.Lookup(pid, ssl); ok {
		t.Error("fd map entry still present after SSL_free")
	}
}

func TestCaptureTLS_SweepEmitsAbandoned(t *testing.T) {
	const pid, ssl, fd = uint32(9), uint64(0x333), int32(4)
	req := []byte("GET /hang HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")

	rd := &slowReader{
		records: []ringbuf.Record{
			{RawSample: marshalSSLEvent(t, sslWriteEvent(pid, pid, ssl, req))},
		},
		delay: 20 * time.Millisecond,
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
