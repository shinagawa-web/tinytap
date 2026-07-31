package http

import (
	"strconv"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/events"
)

// TestFeedSSL_ReassemblesMultiCallBody is FeedSSL's version of
// TestSSLEventsReassembleThroughExistingParserStream: a response whose
// headers and body arrive via two separate SSL_write() calls reassembles
// into one Message, this time via the SSL*-keyed stream directly — no fd,
// no tls.FromSSL translation (#179). Confirms the fd-less path gets the
// same reassembly guarantee #148 established for the fd-resolvable one.
func TestFeedSSL_ReassemblesMultiCallBody(t *testing.T) {
	const pid = uint32(42)
	const ssl = uint64(0xc0ffee)
	body := []byte(`{"ok":true}`)
	headers := []byte("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n")

	p := NewParser()

	e1 := makeSSLEvent(events.SSLOpWrite, pid, pid, ssl, headers)
	if got := p.FeedSSL(e1); len(got) != 0 {
		t.Fatalf("after headers-only SSL_write(): want no message yet, got %+v", got)
	}

	e2 := makeSSLEvent(events.SSLOpWrite, pid, pid, ssl, body)
	got := p.FeedSSL(e2)
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

func TestFeedSSL_ReadReassemblesAcrossCalls(t *testing.T) {
	const pid = uint32(43)
	const ssl = uint64(0xdeadbeef)
	body := []byte("field=value")
	headers := []byte("POST /submit HTTP/1.1\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n")

	p := NewParser()

	e1 := makeSSLEvent(events.SSLOpRead, pid, pid, ssl, headers)
	if got := p.FeedSSL(e1); len(got) != 0 {
		t.Fatalf("after headers-only SSL_read(): want no message yet, got %+v", got)
	}

	e2 := makeSSLEvent(events.SSLOpRead, pid, pid, ssl, body)
	got := p.FeedSSL(e2)
	if len(got) != 1 {
		t.Fatalf("after body SSL_read(): want 1 reassembled message, got %d", len(got))
	}
	if got[0].Req.method != "POST" {
		t.Errorf("method = %q, want POST", got[0].Req.method)
	}
}

// TestFeedSSL_SetsSSLFallbackFields confirms every Message FeedSSL produces
// carries SSL/SSLFallback — the discriminator Pairer needs to route pairing
// through its SSL*-keyed identity space (#171) instead of guessing an fd.
func TestFeedSSL_SetsSSLFallbackFields(t *testing.T) {
	const pid, ssl = uint32(1), uint64(0x123)
	req := []byte("GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")

	p := NewParser()
	got := p.FeedSSL(makeSSLEvent(events.SSLOpWrite, pid, pid, ssl, req))
	if len(got) != 1 {
		t.Fatalf("want 1 message, got %d", len(got))
	}
	if !got[0].SSLFallback || got[0].SSL != ssl {
		t.Errorf("SSLFallback=%v SSL=%#x, want true/%#x", got[0].SSLFallback, got[0].SSL, ssl)
	}
	if got[0].Fd != 0 {
		t.Errorf("Fd = %d, want 0 (meaningless for an SSLFallback message)", got[0].Fd)
	}
}

func TestFeedSSL_UnsupportedOpReturnsNil(t *testing.T) {
	p := NewParser()
	e := makeSSLEvent(events.SSLOpFree, 1, 1, 1, nil)
	if got := p.FeedSSL(e); got != nil {
		t.Errorf("FeedSSL(SSLOpFree) = %+v, want nil", got)
	}
}

func TestFeedSSL_ZeroLenReturnsNil(t *testing.T) {
	p := NewParser()
	e := makeSSLEvent(events.SSLOpWrite, 1, 1, 1, nil)
	if got := p.FeedSSL(e); got != nil {
		t.Errorf("FeedSSL(zero-length payload) = %+v, want nil", got)
	}
}

// TestFeedSSLPayloadLenExceedsArray mirrors TestFeedPayloadLenExceedsArray:
// FeedSSL clamps PayloadLen to len(e.Payload) when the field exceeds the
// array size. Unreachable via a real BPF event but must not panic.
func TestFeedSSLPayloadLenExceedsArray(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	e := &events.SSLEvent{
		Pid:        1,
		SSL:        1,
		Op:         events.SSLOpWrite,
		Len:        uint32(len(req)),
		PayloadLen: events.MaxSSLPayload + 100, // beyond array bounds
	}
	copy(e.Payload[:], req)

	p := NewParser()
	_ = p.FeedSSL(e) // must not panic
}

// TestFeedSSL_DistinctSSLPointersDontCollide confirms two different SSL*
// values on the same pid get independent streams — a HEAD-framing decision
// queued for one connection must never leak into the other.
func TestFeedSSL_DistinctSSLPointersDontCollide(t *testing.T) {
	const pid = uint32(7)
	p := NewParser()

	// Connection A: a HEAD request queues "HEAD" for response framing.
	p.FeedSSL(makeSSLEvent(events.SSLOpWrite, pid, pid, 0xaaaa,
		[]byte("HEAD / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")))

	// Connection B: a GET response with a body arrives on a *different*
	// SSL* — if streams collided, B's response would wrongly pop A's
	// queued HEAD method and drop its body.
	got := p.FeedSSL(makeSSLEvent(events.SSLOpRead, pid, pid, 0xbbbb,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")))

	if len(got) != 1 {
		t.Fatalf("want 1 message on connection B, got %d", len(got))
	}
	if len(got[0].BodySample) != 5 {
		t.Errorf("BodySample = %q, want a 5-byte body (not suppressed by A's queued HEAD)", got[0].BodySample)
	}
}

// TestFeedSSLNeverCollidesWithFdKeyedStream confirms the sslFallback
// discriminator keeps Feed's fd-keyed streams and FeedSSL's SSL*-keyed
// streams apart even when the numeric fd and SSL* values coincide —
// mirrors Pairer's identical guarantee (TestPairerSSLFallbackNeverCollidesWithSameNumericFd).
func TestFeedSSLNeverCollidesWithFdKeyedStream(t *testing.T) {
	const pid = uint32(9)
	const sameValue = 55
	p := NewParser()

	// fd-keyed HEAD request on fd=55.
	p.Feed(makeEvent(events.SyscallWrite, pid, sameValue,
		uint32(len("HEAD / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")),
		[]byte("HEAD / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")))

	// SSL*-keyed response with SSL == 55 (same numeric value as the fd
	// above) carrying a body — must not be suppressed by the fd-keyed HEAD.
	got := p.FeedSSL(makeSSLEvent(events.SSLOpRead, pid, pid, uint64(sameValue),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")))

	if len(got) != 1 || len(got[0].BodySample) != 5 {
		t.Fatalf("want 1 message with a 5-byte body, got %+v", got)
	}
}

// TestCloseSSL_EvictsStreamAndPendingMethods confirms CloseSSL clears both
// directions' stream state and the pendingMethods entry — a subsequent
// FeedSSL for the same (pid, SSL*) must start fresh, not resume orphaned
// state (e.g. a HEAD method queued before the close leaking into a later,
// unrelated connection that happens to reuse the same SSL* value).
func TestCloseSSL_EvictsStreamAndPendingMethods(t *testing.T) {
	const pid, ssl = uint32(3), uint64(0x999)
	p := NewParser()

	p.FeedSSL(makeSSLEvent(events.SSLOpWrite, pid, pid, ssl,
		[]byte("HEAD / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")))
	if len(p.pendingMethods) == 0 {
		t.Fatal("expected pendingMethods to be populated before CloseSSL")
	}

	p.CloseSSL(pid, ssl)

	if _, ok := p.pendingMethods[pendingKey{pid: pid, ssl: ssl, sslFallback: true}]; ok {
		t.Error("CloseSSL: pendingMethods entry not evicted")
	}
	if _, ok := p.streams[connKey{pid: pid, ssl: ssl, sslFallback: true, dir: dirOutgoing}]; ok {
		t.Error("CloseSSL: outgoing stream not evicted")
	}

	// A fresh response on the same SSL* must not see the pre-close HEAD.
	got := p.FeedSSL(makeSSLEvent(events.SSLOpRead, pid, pid, ssl,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")))
	if len(got) != 1 || len(got[0].BodySample) != 5 {
		t.Fatalf("want 1 message with a 5-byte body after CloseSSL, got %+v", got)
	}
}

// TestCloseSSL_NeverEvictsFdKeyedStream is CloseSSL's half of the
// discriminator guarantee; TestFeedSSLNeverCollidesWithFdKeyedStream covers
// the Feed/FeedSSL production side.
func TestCloseSSL_NeverEvictsFdKeyedStream(t *testing.T) {
	const pid = uint32(11)
	const sameValue = 21
	p := NewParser()

	p.Feed(makeEvent(events.SyscallWrite, pid, sameValue,
		uint32(len("HEAD / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")),
		[]byte("HEAD / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")))

	p.CloseSSL(pid, uint64(sameValue))

	if _, ok := p.pendingMethods[pendingKey{pid: pid, fd: sameValue}]; !ok {
		t.Error("CloseSSL must not evict an fd-keyed pendingMethods entry with the same numeric value")
	}
}
