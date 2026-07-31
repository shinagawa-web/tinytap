package http

import (
	"strconv"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/tls"
)

// makeSSLEvent mirrors makeEvent (parser_test.go) for the SSL uprobe path.
func makeSSLEvent(op uint32, pid, tid uint32, ssl uint64, sample []byte) *events.SSLEvent {
	e := &events.SSLEvent{Pid: pid, Tid: tid, SSL: ssl, Op: op}
	n := len(sample)
	if n > len(e.Payload) {
		n = len(e.Payload)
	}
	copy(e.Payload[:n], sample[:n])
	e.PayloadLen = uint32(n)
	e.Len = uint32(len(sample))
	return e
}

// TestSSLEventsReassembleThroughExistingParserStream is the concrete
// verification #148 asked for: a logical HTTP response whose headers and
// body arrive via two separate SSL_write() calls (two uprobe firings, two
// SSLEvents) reassembles into one Message with no change to Parser itself.
// tls.FromSSL only needs to produce one Event per SSL call — the existing
// per-(pid, fd) stream accumulation in Parser.Feed does the reassembly, the
// same way it already does for a plaintext body split across multiple
// write() syscalls (see TestBodySplitAcrossMultipleSyscalls).
func TestSSLEventsReassembleThroughExistingParserStream(t *testing.T) {
	const pid, fd = uint32(999), int32(4)
	body := []byte(`{"ok":true}`)
	headers := []byte("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n")

	p := NewParser()

	// SSL_write() call 1: headers only.
	e1 := makeSSLEvent(events.SSLOpWrite, pid, pid, 0xabc, headers)
	ev1, ok := tls.FromSSL(e1, fd)
	if !ok {
		t.Fatal("FromSSL: want ok=true")
	}
	if got := p.Feed(&ev1); len(got) != 0 {
		t.Fatalf("after headers-only SSL_write(): want no message yet (body pending), got %+v", got)
	}

	// SSL_write() call 2: body, in a separate application-level call — this
	// is the multi-call scenario #148 needs reassembled.
	e2 := makeSSLEvent(events.SSLOpWrite, pid, pid, 0xabc, body)
	ev2, ok := tls.FromSSL(e2, fd)
	if !ok {
		t.Fatal("FromSSL: want ok=true")
	}
	got := p.Feed(&ev2)
	if len(got) != 1 {
		t.Fatalf("after body SSL_write(): want 1 reassembled message, got %d", len(got))
	}
	if got[0].Res.status != 200 {
		t.Errorf("status = %d, want 200", got[0].Res.status)
	}
	if string(got[0].BodySample) != string(body) {
		t.Errorf("body = %q, want %q", got[0].BodySample, body)
	}
}

// TestSSLReadEventsReassembleAcrossCalls mirrors the write-side test for
// SSL_read(): a request whose body a client reads back via two separate
// SSL_read() calls still reassembles into one Message.
func TestSSLReadEventsReassembleAcrossCalls(t *testing.T) {
	const pid, fd = uint32(1000), int32(9)
	body := []byte("field=value")
	headers := []byte("POST /submit HTTP/1.1\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n")

	p := NewParser()

	e1 := makeSSLEvent(events.SSLOpRead, pid, pid, 0xdef, headers)
	ev1, ok := tls.FromSSL(e1, fd)
	if !ok {
		t.Fatal("FromSSL: want ok=true")
	}
	if got := p.Feed(&ev1); len(got) != 0 {
		t.Fatalf("after headers-only SSL_read(): want no message yet, got %+v", got)
	}

	e2 := makeSSLEvent(events.SSLOpRead, pid, pid, 0xdef, body)
	ev2, ok := tls.FromSSL(e2, fd)
	if !ok {
		t.Fatal("FromSSL: want ok=true")
	}
	got := p.Feed(&ev2)
	if len(got) != 1 {
		t.Fatalf("after body SSL_read(): want 1 reassembled message, got %d", len(got))
	}
	if got[0].Req.method != "POST" {
		t.Errorf("method = %q, want POST", got[0].Req.method)
	}
	if string(got[0].BodySample) != string(body) {
		t.Errorf("body = %q, want %q", got[0].BodySample, body)
	}
}
