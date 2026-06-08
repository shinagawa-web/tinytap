package main

import (
	"testing"
)

// makeEvent builds a synthetic BPF event. wireBytes is the syscall's true
// wire byte count; the payload is the (possibly truncated) sample.
func makeEvent(syscall uint32, pid uint32, fd int32, wireBytes uint32, sample []byte) *Event {
	e := &Event{
		Pid:     pid,
		Fd:      fd,
		Bytes:   wireBytes,
		Syscall: syscall,
	}
	n := len(sample)
	if n > len(e.Payload) {
		n = len(e.Payload)
	}
	copy(e.Payload[:n], sample[:n])
	e.PayloadLen = uint32(n)
	return e
}

// Body delivered across several syscalls, each carrying wire bytes >
// MAX_PAYLOAD. Verifies that subsequent events correctly debit Event.Bytes
// instead of the (capped) sample length. Regression test for: stateNeedBody
// was decrementing bodyRemaining by len(buf) (sample bytes, capped at
// MAX_PAYLOAD), so a body > 256 bytes left bodyRemaining permanently
// positive — and the next keep-alive message was mis-attributed as body.
func TestBodySplitAcrossMultipleSyscalls(t *testing.T) {
	headers := []byte("HTTP/1.1 200 OK\r\nContent-Length: 3000\r\n\r\n")
	chunk := make([]byte, 1000) // sample will be truncated to 256
	for i := range chunk {
		chunk[i] = 'B'
	}

	p := NewHTTPParser()
	pid, fd := uint32(1234), int32(7)

	// Event 1: headers + first 1000 wire bytes of body, sample 256.
	ev1Wire := append(append([]byte{}, headers...), chunk...)
	ev1 := makeEvent(syscallWrite, pid, fd, uint32(len(headers)+len(chunk)), ev1Wire)
	if got := p.Feed(ev1); len(got) != 1 || got[0].Res.status != 200 {
		t.Fatalf("event 1: want 1 HTTP event with status 200, got %+v", got)
	}

	// Event 2 and 3: 1000 wire bytes each of pure body.
	ev2 := makeEvent(syscallWrite, pid, fd, uint32(len(chunk)), chunk)
	if got := p.Feed(ev2); len(got) != 0 {
		t.Fatalf("event 2: expected no HTTP events while body drains, got %+v", got)
	}
	ev3 := makeEvent(syscallWrite, pid, fd, uint32(len(chunk)), chunk)
	if got := p.Feed(ev3); len(got) != 0 {
		t.Fatalf("event 3: expected no HTTP events at body completion, got %+v", got)
	}

	// Event 4: next pipelined response — only parses if body framing closed.
	next := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	ev4 := makeEvent(syscallWrite, pid, fd, uint32(len(next)), next)
	got := p.Feed(ev4)
	if len(got) != 1 || got[0].Res.status != 204 {
		t.Fatalf("event 4: want 204 as next message (body framing closed), got %+v", got)
	}
}

// Small body delivered alongside its headers in a single sample. The state
// machine must still recognise the body as fully consumed and parse the
// next pipelined message.
func TestSmallBodyAndNextMessageInSameSyscall(t *testing.T) {
	wire := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
		[]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")...)
	p := NewHTTPParser()
	ev := makeEvent(syscallWrite, 1234, 7, uint32(len(wire)), wire)
	got := p.Feed(ev)
	if len(got) != 2 || got[0].Res.status != 200 || got[1].Res.status != 204 {
		t.Fatalf("want [200, 204], got %+v", got)
	}
}

// HEAD response carries Content-Length but no body (RFC 7230 §3.3.3).
// Without the request-method lookup the parser would wait forever for
// body bytes that never arrive, mis-attributing the next keep-alive
// response as body content.
func TestHeadResponseHasNoBodyDespiteContentLength(t *testing.T) {
	p := NewHTTPParser()
	pid, fd := uint32(1234), int32(7)

	// Client side: HEAD request goes out (write/sendto/sendmsg).
	req := []byte("HEAD /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
	if got := p.Feed(makeEvent(syscallWrite, pid, fd, uint32(len(req)), req)); len(got) != 1 || !got[0].IsRequest || got[0].Req.method != "HEAD" {
		t.Fatalf("HEAD request: want 1 request event, got %+v", got)
	}

	// Server's reply: HEAD response advertises 1000 bytes but sends none.
	// Next pipelined response (200 OK) follows immediately.
	resp1 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
	resp2 := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	wire := append(append([]byte{}, resp1...), resp2...)
	got := p.Feed(makeEvent(syscallRead, pid, fd, uint32(len(wire)), wire))
	if len(got) != 2 || got[0].Res.status != 200 || got[1].Res.status != 204 {
		t.Fatalf("HEAD/next: want [200, 204], got %+v", got)
	}
}

// 1xx, 204, 304 responses have no body regardless of any Content-Length
// header. The parser must consume them as zero-length and immediately
// look for the next message.
func TestStatusCodesWithNoBody(t *testing.T) {
	cases := []struct {
		name   string
		status string
		code   int
	}{
		{"100 Continue", "100 Continue", 100},
		{"204 No Content", "204 No Content", 204},
		{"304 Not Modified", "304 Not Modified", 304},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewHTTPParser()
			// Buggy / weird origin: declares Content-Length but the status
			// forbids a body. Pair with a follow-up 200 to confirm framing.
			resp1 := []byte("HTTP/1.1 " + tc.status + "\r\nContent-Length: 1000\r\n\r\n")
			resp2 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			wire := append(append([]byte{}, resp1...), resp2...)
			got := p.Feed(makeEvent(syscallWrite, 1234, 7, uint32(len(wire)), wire))
			if len(got) != 2 || got[0].Res.status != tc.code || got[1].Res.status != 200 {
				t.Fatalf("want [%d, 200], got %+v", tc.code, got)
			}
		})
	}
}
