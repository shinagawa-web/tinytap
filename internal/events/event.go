// Package events defines the shape of a single observation from BPF and
// the protocol-agnostic decoder that turns a ringbuf record into an
// Event. Per-protocol parsers (under internal/protocols/) consume Event
// values without knowing how they were produced.
package events

import (
	"encoding/binary"
	"fmt"
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
const MaxPayload = 4096

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

// eventWireSize is sizeof(struct event) on the C side: the fixed 48-byte
// header (ts_ns through comm) plus the MaxPayload-sized payload array.
const eventWireSize = 48 + MaxPayload

// Decode parses a single ringbuf record into an Event. Returns an error
// only if the buffer is too short or otherwise malformed; partial events
// are not produced.
//
// This decodes fields directly via encoding/binary's byte-slice helpers
// and copy() instead of binary.Read(reader, ..., e): binary.Read falls
// back to reflection for struct targets, and at MaxPayload=4096 (#36) that
// reflection overhead on Event's [4096]byte field was CPU-bound enough,
// per syscall event, to become the actual throughput bottleneck under a
// request burst — confirmed by ruling out ring buffer capacity first (an
// 8x larger ring changed the drop rate by well under 2%).
func Decode(raw []byte, e *Event) error {
	if len(raw) < eventWireSize {
		return fmt.Errorf("events: short ringbuf record: got %d bytes, want %d", len(raw), eventWireSize)
	}
	e.TsNs = binary.LittleEndian.Uint64(raw[0:8])
	e.Pid = binary.LittleEndian.Uint32(raw[8:12])
	e.Tid = binary.LittleEndian.Uint32(raw[12:16])
	e.Fd = int32(binary.LittleEndian.Uint32(raw[16:20]))
	e.Bytes = binary.LittleEndian.Uint32(raw[20:24])
	e.Syscall = binary.LittleEndian.Uint32(raw[24:28])
	e.PayloadLen = binary.LittleEndian.Uint32(raw[28:32])
	copy(e.Comm[:], raw[32:48])
	copy(e.Payload[:], raw[48:eventWireSize])
	return nil
}
