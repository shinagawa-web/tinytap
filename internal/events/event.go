package events

import (
	"encoding/binary"
	"fmt"
)

// Must match the SYS_* enum in bpf/tinytap.bpf.c.
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

const MaxPayload = 4096

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

const eventWireSize = 48 + MaxPayload // sizeof(struct event) in bpf/tinytap.bpf.c

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
