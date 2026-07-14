package events

import (
	"encoding/binary"
	"testing"
)

// makeSSLRaw builds a wire-format ssl_event byte slice matching the C
// struct's explicit layout (bpf/tinytap_uprobe.bpf.c) — including the
// 4-byte alignment pad between payload_len and comm, which SSLEvent has no
// corresponding Go field for since it carries no data.
func makeSSLRaw(e SSLEvent) []byte {
	raw := make([]byte, sslEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], e.TsNs)
	binary.LittleEndian.PutUint32(raw[8:12], e.Pid)
	binary.LittleEndian.PutUint32(raw[12:16], e.Tid)
	binary.LittleEndian.PutUint64(raw[16:24], e.SSL)
	binary.LittleEndian.PutUint32(raw[24:28], e.Op)
	binary.LittleEndian.PutUint32(raw[28:32], e.Len)
	binary.LittleEndian.PutUint32(raw[32:36], e.PayloadLen)
	copy(raw[40:56], e.Comm[:])
	copy(raw[56:sslEventWireSize], e.Payload[:])
	return raw
}

func TestDecodeSSLHappyPath(t *testing.T) {
	want := SSLEvent{
		TsNs:       1_234_567_890,
		Pid:        42,
		Tid:        43,
		SSL:        0xdeadbeef,
		Op:         SSLOpRead,
		Len:        5,
		PayloadLen: 5,
	}
	copy(want.Comm[:], "nginx")
	copy(want.Payload[:], "hello")

	var got SSLEvent
	if err := DecodeSSL(makeSSLRaw(want), &got); err != nil {
		t.Fatalf("DecodeSSL returned unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestDecodeSSLShortBufferError(t *testing.T) {
	var e SSLEvent
	if err := DecodeSSL([]byte{0x00, 0x01}, &e); err == nil {
		t.Error("DecodeSSL should return an error for a too-short buffer")
	}
}
