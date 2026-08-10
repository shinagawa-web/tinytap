package events

import (
	"encoding/binary"
	"fmt"
)

// Must match enum ssl_op in bpf/tinytap_uprobe.bpf.c.
const (
	SSLOpWrite = 1 // Len is the requested byte count
	SSLOpRead  = 2 // Len is the actual byte count
	SSLOpFree  = 3 // Len and Payload are unused
)

const MaxSSLPayload = 4096

type SSLEvent struct {
	TsNs       uint64
	Pid        uint32
	Tid        uint32
	SSL        uint64
	Op         uint32
	Len        uint32
	PayloadLen uint32
	Comm       [16]byte
	Payload    [MaxSSLPayload]byte
}

const sslEventWireSize = 56 + MaxSSLPayload // sizeof(struct ssl_event), including the offset 36-40 alignment pad

func DecodeSSL(raw []byte, e *SSLEvent) error {
	if len(raw) < sslEventWireSize {
		return fmt.Errorf("events: short ssl ringbuf record: got %d bytes, want %d", len(raw), sslEventWireSize)
	}
	e.TsNs = binary.LittleEndian.Uint64(raw[0:8])
	e.Pid = binary.LittleEndian.Uint32(raw[8:12])
	e.Tid = binary.LittleEndian.Uint32(raw[12:16])
	e.SSL = binary.LittleEndian.Uint64(raw[16:24])
	e.Op = binary.LittleEndian.Uint32(raw[24:28])
	e.Len = binary.LittleEndian.Uint32(raw[28:32])
	e.PayloadLen = binary.LittleEndian.Uint32(raw[32:36])
	copy(e.Comm[:], raw[40:56])
	copy(e.Payload[:], raw[56:sslEventWireSize])
	return nil
}
