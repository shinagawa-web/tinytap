package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

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
}

func (s *fakeSink) OnEvent(*events.Event)         { s.eventCount++ }
func (s *fakeSink) OnMessage(httpproto.Message)    { s.messageCount++ }
func (s *fakeSink) OnPaired(httpproto.PairedEvent) { s.pairedCount++ }
func (s *fakeSink) Close() error                   { return nil }

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
