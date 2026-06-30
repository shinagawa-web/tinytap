// Package events defines the shape of a single observation from BPF and
// the protocol-agnostic decoder that turns a ringbuf record into an
// Event. Per-protocol parsers (under internal/protocols/) consume Event
// values without knowing how they were produced.
package events

import (
	"bytes"
	"encoding/binary"
)

// Syscall identifiers. Must match the SYS_* enum in bpf/tinytap.bpf.c.
const (
	SyscallAccept4  = 1
	SyscallRead     = 2
	SyscallWrite    = 3
	SyscallClose    = 4
	SyscallRecvfrom = 5
	SyscallSendto   = 6
	SyscallRecvmsg  = 7
	SyscallSendmsg  = 8
	SyscallWritev   = 9
	SyscallReadv    = 10
	SyscallSendfile = 11
)

// MaxPayload is the payload sample cap on the BPF side (MAX_PAYLOAD in
// bpf/tinytap.bpf.c). Sampled bytes may be shorter than the syscall's
// actual wire byte count; consumers that care about wire-level framing
// must read Event.Bytes, not len(Event.Payload).
const MaxPayload = 256

// Event mirrors the C `struct event` emitted by the BPF program. Field
// order, sizes, and alignment must stay in lockstep with the C struct —
// the wire format is binary.Read of the ringbuf record bytes.
type Event struct {
	TsNs       uint64
	Pid        uint32
	Tid        uint32
	Fd         int32
	Bytes      uint32
	Syscall    uint32
	PayloadLen uint32
	Comm       [16]byte
	Payload    [MaxPayload]byte
}

// SyscallNames maps syscall IDs back to human-readable strings for
// rendering raw event lines.
var SyscallNames = map[uint32]string{
	SyscallAccept4:  "accept4",
	SyscallRead:     "read",
	SyscallWrite:    "write",
	SyscallClose:    "close",
	SyscallRecvfrom: "recvfrom",
	SyscallSendto:   "sendto",
	SyscallRecvmsg:  "recvmsg",
	SyscallSendmsg:  "sendmsg",
	SyscallWritev:   "writev",
	SyscallReadv:    "readv",
	SyscallSendfile: "sendfile",
}

// Decode parses a single ringbuf record into an Event. Returns an error
// only if the buffer is too short or otherwise malformed; partial events
// are not produced.
func Decode(raw []byte, e *Event) error {
	return binary.Read(bytes.NewReader(raw), binary.LittleEndian, e)
}
