package events

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func makeRaw(e Event) []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, e); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func TestDecodeHappyPath(t *testing.T) {
	want := Event{
		TsNs:       1_234_567_890,
		Pid:        42,
		Tid:        43,
		Fd:         7,
		Bytes:      1024,
		Syscall:    SyscallWrite,
		PayloadLen: 5,
	}
	copy(want.Comm[:], "python3")
	copy(want.Payload[:], "hello")

	var got Event
	if err := Decode(makeRaw(want), &got); err != nil {
		t.Fatalf("Decode returned unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestDecodeShortBufferError(t *testing.T) {
	var e Event
	if err := Decode([]byte{0x00, 0x01}, &e); err == nil {
		t.Error("Decode should return an error for a too-short buffer")
	}
}
