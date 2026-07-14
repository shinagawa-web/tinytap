package events

import (
	"encoding/binary"
	"fmt"
)

// SSL plaintext op identifiers. Must match enum ssl_op in bpf/tinytap_uprobe.bpf.c.
const (
	SSLOpWrite = 1 // captured at SSL_write/SSL_write_ex entry; Len is the requested byte count
	SSLOpRead  = 2 // captured at SSL_read/SSL_read_ex return; Len is the actual byte count
)

// MaxSSLPayload is the payload sample cap on the BPF side (MAX_SSL_PAYLOAD in
// bpf/tinytap_uprobe.bpf.c).
const MaxSSLPayload = 4096

// SSLEvent mirrors the C `struct ssl_event` emitted by the SSL_write/SSL_read
// uprobe program (#146). Field order, sizes, and alignment must stay in
// lockstep with the C struct — the wire format is decoded directly from raw
// ringbuf record bytes (see DecodeSSL).
//
// Unlike Event, SSLEvent carries no fd: correlating SSL to fd is a separate
// concern handled by the SSL_set_fd uprobe (#147, loader.SSLFdProbe).
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

// sslEventWireSize is sizeof(struct ssl_event) on the C side: the fixed
// 56-byte header (ts_ns through comm, including the alignment pad at offset
// 36-40) plus the MaxSSLPayload-sized payload array.
const sslEventWireSize = 56 + MaxSSLPayload

// DecodeSSL parses a single ringbuf record from the SSL uprobe program into
// an SSLEvent. Returns an error only if the buffer is too short or otherwise
// malformed; partial events are not produced.
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
