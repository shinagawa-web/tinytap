package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/output"
	httpproto "github.com/shinagawa-web/tinytap/internal/protocols/http"
)

type fakeReader struct {
	records []ringbuf.Record
	idx     int
}

func (f *fakeReader) Read() (ringbuf.Record, error) {
	if f.idx >= len(f.records) {
		return ringbuf.Record{}, errors.New("EOF")
	}
	rec := f.records[f.idx]
	f.idx++
	return rec, nil
}

type fakeSink struct {
	eventCount   int
	messageCount int
	pairedCount  int
	closeErr     error
}

func (s *fakeSink) OnEvent(*events.Event)         { s.eventCount++ }
func (s *fakeSink) OnMessage(httpproto.Message)    { s.messageCount++ }
func (s *fakeSink) OnPaired(httpproto.PairedEvent) { s.pairedCount++ }
func (s *fakeSink) Close() error                   { return s.closeErr }

var _ output.Sink = (*fakeSink)(nil)

func marshalEvent(t *testing.T, e events.Event) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, e); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCapture_ReaderErrorImmediately(t *testing.T) {
	rd := &fakeReader{}
	sink := &fakeSink{}
	capture(rd, sink)
	if sink.eventCount != 0 {
		t.Errorf("want 0 events, got %d", sink.eventCount)
	}
}

func TestCapture_MalformedBytes(t *testing.T) {
	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: []byte{0x01, 0x02}},
		},
	}
	sink := &fakeSink{}
	capture(rd, sink)
	if sink.eventCount != 0 {
		t.Errorf("want 0 events on decode error, got %d", sink.eventCount)
	}
}

func TestCapture_ValidEvent(t *testing.T) {
	e := events.Event{Syscall: events.SyscallWrite, Pid: 1, Fd: 3}
	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: marshalEvent(t, e)},
		},
	}
	sink := &fakeSink{}
	capture(rd, sink)
	if sink.eventCount != 1 {
		t.Errorf("want 1 event, got %d", sink.eventCount)
	}
}

func TestCapture_CloseEvent(t *testing.T) {
	e := events.Event{Syscall: events.SyscallClose, Pid: 42, Fd: 7}
	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: marshalEvent(t, e)},
		},
	}
	sink := &fakeSink{}
	capture(rd, sink)
	if sink.eventCount != 1 {
		t.Errorf("want 1 event, got %d", sink.eventCount)
	}
}

func httpEvent(syscall uint32, pid uint32, fd int32, payload []byte) events.Event {
	e := events.Event{
		Syscall: syscall,
		Pid:     pid,
		Fd:      fd,
		Bytes:   uint32(len(payload)),
	}
	n := copy(e.Payload[:], payload)
	e.PayloadLen = uint32(n)
	return e
}

func TestCapture_HTTPExchange(t *testing.T) {
	const pid, fd = uint32(1), int32(3)
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: marshalEvent(t, httpEvent(events.SyscallWrite, pid, fd, req))},
			{RawSample: marshalEvent(t, httpEvent(events.SyscallRead, pid, fd, resp))},
		},
	}
	sink := &fakeSink{}
	capture(rd, sink)

	if sink.messageCount != 2 {
		t.Errorf("want 2 messages, got %d", sink.messageCount)
	}
	if sink.pairedCount != 1 {
		t.Errorf("want 1 paired event, got %d", sink.pairedCount)
	}
}

// TestCapture_CloseEmitsAbandoned verifies that a request with no response
// followed by a close event surfaces as an abandoned PairedEvent via OnPaired.
func TestCapture_CloseEmitsAbandoned(t *testing.T) {
	const pid, fd = uint32(5), int32(9)
	req := []byte("GET /slow HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")

	// request arrives, then the fd is closed with no response
	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: marshalEvent(t, httpEvent(events.SyscallWrite, pid, fd, req))},
			{RawSample: marshalEvent(t, events.Event{Syscall: events.SyscallClose, Pid: pid, Fd: fd})},
		},
	}
	sink := &abandonedSink{}
	capture(rd, sink)

	if len(sink.paired) != 1 {
		t.Fatalf("want 1 paired (abandoned) event, got %d", len(sink.paired))
	}
	pe := sink.paired[0]
	if !pe.Abandoned {
		t.Error("PairedEvent.Abandoned must be true")
	}
	if pe.AbandonReason != httpproto.AbandonReasonClosed {
		t.Errorf("AbandonReason = %q, want %q", pe.AbandonReason, httpproto.AbandonReasonClosed)
	}
	if pe.Method != "GET" || pe.Path != "/slow" {
		t.Errorf("method/path = %q %q, want GET /slow", pe.Method, pe.Path)
	}
}

type abandonedSink struct {
	paired []httpproto.PairedEvent
}

func (s *abandonedSink) OnEvent(*events.Event)             {}
func (s *abandonedSink) OnMessage(httpproto.Message)       {}
func (s *abandonedSink) OnPaired(pe httpproto.PairedEvent) { s.paired = append(s.paired, pe) }
func (s *abandonedSink) Close() error                      { return nil }

// slowReader returns the given records then blocks until the ticker fires,
// simulating a hung connection.  After the delay it returns EOF.
type slowReader struct {
	records []ringbuf.Record
	idx     int
	delay   time.Duration
}

func (r *slowReader) Read() (ringbuf.Record, error) {
	if r.idx < len(r.records) {
		rec := r.records[r.idx]
		r.idx++
		return rec, nil
	}
	time.Sleep(r.delay)
	return ringbuf.Record{}, errors.New("EOF")
}

// TestCapture_SweepEmitsAbandoned verifies that the sweeper goroutine evicts a
// pending request that has been waiting longer than the timeout.
func TestCapture_SweepEmitsAbandoned(t *testing.T) {
	const pid, fd = uint32(9), int32(4)
	req := []byte("GET /hang HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")

	sink := &abandonedSink{}
	// interval=1ms, timeout=1ms: the sweeper fires almost immediately and
	// the request (added at t=0) is already older than 1ms.
	rd := &slowReader{
		records: []ringbuf.Record{
			{RawSample: marshalEvent(t, httpEvent(events.SyscallWrite, pid, fd, req))},
		},
		delay: 20 * time.Millisecond, // keep capture alive long enough for sweep
	}
	captureWithOptions(rd, sink, 1*time.Millisecond, 1*time.Millisecond)

	var abandoned []httpproto.PairedEvent
	for _, pe := range sink.paired {
		if pe.Abandoned {
			abandoned = append(abandoned, pe)
		}
	}
	if len(abandoned) == 0 {
		t.Fatal("want at least 1 abandoned event from sweeper, got 0")
	}
	if abandoned[0].AbandonReason != httpproto.AbandonReasonTimeout {
		t.Errorf("AbandonReason = %q, want %q", abandoned[0].AbandonReason, httpproto.AbandonReasonTimeout)
	}
}

func TestCapture_MultipleEvents(t *testing.T) {
	e1 := events.Event{Syscall: events.SyscallRead, Pid: 1, Fd: 3}
	e2 := events.Event{Syscall: events.SyscallWrite, Pid: 1, Fd: 3}
	rd := &fakeReader{
		records: []ringbuf.Record{
			{RawSample: marshalEvent(t, e1)},
			{RawSample: marshalEvent(t, e2)},
		},
	}
	sink := &fakeSink{}
	capture(rd, sink)
	if sink.eventCount != 2 {
		t.Errorf("want 2 events, got %d", sink.eventCount)
	}
}
