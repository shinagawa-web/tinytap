package tls_test

import (
	"testing"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/tls"
)

// makeSSLEvent builds a synthetic SSL uprobe event, mirroring parser_test.go's
// makeEvent helper for the plaintext syscall path.
func makeSSLEvent(op uint32, pid, tid uint32, ssl uint64, sample []byte) *events.SSLEvent {
	e := &events.SSLEvent{
		Pid: pid,
		Tid: tid,
		SSL: ssl,
		Op:  op,
	}
	n := len(sample)
	if n > len(e.Payload) {
		n = len(e.Payload)
	}
	copy(e.Payload[:n], sample[:n])
	e.PayloadLen = uint32(n)
	e.Len = uint32(len(sample))
	return e
}

func TestFromSSL_MapsWriteFields(t *testing.T) {
	e := makeSSLEvent(events.SSLOpWrite, 1234, 5678, 0xdeadbeef, []byte("hello"))
	got, ok := tls.FromSSL(e, 42)
	if !ok {
		t.Fatal("FromSSL: want ok=true for SSLOpWrite")
	}
	if got.Pid != 1234 || got.Tid != 5678 || got.Fd != 42 {
		t.Errorf("FromSSL: Pid/Tid/Fd = %d/%d/%d, want 1234/5678/42", got.Pid, got.Tid, got.Fd)
	}
	if got.Syscall != events.SyscallWrite {
		t.Errorf("FromSSL: Syscall = %d, want SyscallWrite", got.Syscall)
	}
	if got.Bytes != 5 || got.PayloadLen != 5 {
		t.Errorf("FromSSL: Bytes/PayloadLen = %d/%d, want 5/5", got.Bytes, got.PayloadLen)
	}
	if string(got.Payload[:got.PayloadLen]) != "hello" {
		t.Errorf("FromSSL: payload = %q, want %q", got.Payload[:got.PayloadLen], "hello")
	}
}

func TestFromSSL_ReadOpMapsToSyscallRead(t *testing.T) {
	e := makeSSLEvent(events.SSLOpRead, 1, 1, 1, []byte("x"))
	got, ok := tls.FromSSL(e, 7)
	if !ok {
		t.Fatal("FromSSL: want ok=true for SSLOpRead")
	}
	if got.Syscall != events.SyscallRead {
		t.Errorf("FromSSL: Syscall = %d, want SyscallRead", got.Syscall)
	}
}

func TestFromSSL_UnsupportedOpRejected(t *testing.T) {
	e := makeSSLEvent(99, 1, 1, 1, nil)
	if _, ok := tls.FromSSL(e, 7); ok {
		t.Error("FromSSL: want ok=false for an op that isn't SSLOpWrite/SSLOpRead")
	}
}

func TestFromSSL_PayloadTruncatedByWireLenNotLost(t *testing.T) {
	// Len (the SSL-level requested/actual byte count) can exceed PayloadLen
	// when the uprobe's own MAX_SSL_PAYLOAD sample cap truncated it — mirrors
	// events.Event.Bytes vs PayloadLen for an oversized syscall. FromSSL must
	// carry both through unchanged rather than collapsing them to one value.
	e := makeSSLEvent(events.SSLOpWrite, 1, 1, 1, []byte("abc"))
	e.Len = 5000 // BPF-side truncated the sample; requested length was larger
	got, ok := tls.FromSSL(e, 7)
	if !ok {
		t.Fatal("FromSSL: want ok=true")
	}
	if got.Bytes != 5000 {
		t.Errorf("FromSSL: Bytes = %d, want 5000 (wire length, not sample length)", got.Bytes)
	}
	if got.PayloadLen != 3 {
		t.Errorf("FromSSL: PayloadLen = %d, want 3 (actual sample bytes)", got.PayloadLen)
	}
}
