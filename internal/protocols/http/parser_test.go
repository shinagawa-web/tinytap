package http

import (
	"testing"

	"github.com/shinagawa-web/tinytap/internal/events"
)

// makeEvent builds a synthetic BPF event. wireBytes is the syscall's true
// wire byte count; the payload is the (possibly truncated) sample.
func makeEvent(syscall uint32, pid uint32, fd int32, wireBytes uint32, sample []byte) *events.Event {
	e := &events.Event{
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

	p := NewParser()
	pid, fd := uint32(1234), int32(7)

	// Event 1: headers + first 1000 wire bytes of body, sample 256.
	ev1Wire := append(append([]byte{}, headers...), chunk...)
	ev1 := makeEvent(events.SyscallWrite, pid, fd, uint32(len(headers)+len(chunk)), ev1Wire)
	if got := p.Feed(ev1); len(got) != 1 || got[0].Res.status != 200 {
		t.Fatalf("event 1: want 1 HTTP event with status 200, got %+v", got)
	}

	// Event 2 and 3: 1000 wire bytes each of pure body.
	ev2 := makeEvent(events.SyscallWrite, pid, fd, uint32(len(chunk)), chunk)
	if got := p.Feed(ev2); len(got) != 0 {
		t.Fatalf("event 2: expected no HTTP events while body drains, got %+v", got)
	}
	ev3 := makeEvent(events.SyscallWrite, pid, fd, uint32(len(chunk)), chunk)
	if got := p.Feed(ev3); len(got) != 0 {
		t.Fatalf("event 3: expected no HTTP events at body completion, got %+v", got)
	}

	// Event 4: next pipelined response — only parses if body framing closed.
	next := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	ev4 := makeEvent(events.SyscallWrite, pid, fd, uint32(len(next)), next)
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
	p := NewParser()
	ev := makeEvent(events.SyscallWrite, 1234, 7, uint32(len(wire)), wire)
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
	p := NewParser()
	pid, fd := uint32(1234), int32(7)

	// Client side: HEAD request goes out (write/sendto/sendmsg).
	req := []byte("HEAD /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
	if got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(req)), req)); len(got) != 1 || !got[0].IsRequest || got[0].Req.method != "HEAD" {
		t.Fatalf("HEAD request: want 1 request event, got %+v", got)
	}

	// Server's reply: HEAD response advertises 1000 bytes but sends none.
	// Next pipelined response (200 OK) follows immediately.
	resp1 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
	resp2 := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	wire := append(append([]byte{}, resp1...), resp2...)
	got := p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(wire)), wire))
	if len(got) != 2 || got[0].Res.status != 200 || got[1].Res.status != 204 {
		t.Fatalf("HEAD/next: want [200, 204], got %+v", got)
	}
}

// A 1xx informational response precedes a final response for the same
// request. Popping the queued method on the 1xx desynchronises the FIFO,
// so a later pipelined HEAD's slot gets attributed to the wrong response.
// This test exercises the exact bug: a 1xx must peek, not pop.
func TestInformationalResponseDoesNotConsumeMethodQueue(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1234), int32(7)

	// Two pipelined requests: POST with Expect: 100-continue, then HEAD.
	req1 := []byte("POST /upload HTTP/1.1\r\nExpect: 100-continue\r\n\r\n")
	req2 := []byte("HEAD /resource HTTP/1.1\r\nHost: x\r\n\r\n")
	reqWire := append(append([]byte{}, req1...), req2...)
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(reqWire)), reqWire))

	// Server reply stream: 100 Continue → POST's 200 (5-byte body) →
	// HEAD's 200 (Content-Length: 1000 but no body). A 204 follows so we
	// can verify the HEAD's framing closed cleanly and the parser moved on.
	resp1 := []byte("HTTP/1.1 100 Continue\r\n\r\n")
	resp2 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	resp3 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
	resp4 := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	respWire := append(append(append(append([]byte{}, resp1...), resp2...), resp3...), resp4...)
	got := p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(respWire)), respWire))

	if len(got) != 4 {
		t.Fatalf("want [100, 200(POST), 200(HEAD), 204] = 4 events, got %d: %+v", len(got), got)
	}
	statuses := [4]int{got[0].Res.status, got[1].Res.status, got[2].Res.status, got[3].Res.status}
	if statuses != [4]int{100, 200, 200, 204} {
		t.Errorf("status sequence wrong: %v", statuses)
	}
	// POST's response keeps its body — 1xx peek did NOT pop the POST method.
	if got[1].ContentLength != 5 {
		t.Errorf("POST's 200: body should NOT be stripped (ContentLength=%d, want 5)", got[1].ContentLength)
	}
	// HEAD's response gets stripped — the HEAD method was correctly popped.
	if got[2].ContentLength != 0 {
		t.Errorf("HEAD's 200: ContentLength should be 0 (got %d)", got[2].ContentLength)
	}
}

// When two messages arrive in a single syscall (pipeline within one read),
// the second message's Message.TsNs must reflect that syscall's ktime —
// not 0. Regression for: advance() was zeroing messageStartTs after body
// completion, then looping into the next start-line without going back
// through Feed, which is where the ts gets seeded.
func TestPipelinedMessagesInOneSyscallShareTsNs(t *testing.T) {
	p := NewParser()
	wire := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
		[]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")...)
	ev := makeEvent(events.SyscallWrite, 1234, 7, uint32(len(wire)), wire)
	ev.TsNs = 42_000_000_000

	got := p.Feed(ev)
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
	if got[0].TsNs != 42_000_000_000 {
		t.Errorf("first event TsNs: want 42_000_000_000, got %d", got[0].TsNs)
	}
	if got[1].TsNs != 42_000_000_000 {
		t.Errorf("second event TsNs: want 42_000_000_000 (same syscall), got %d", got[1].TsNs)
	}
}

// After a message's body drains exactly at an event boundary, the next
// message arriving in a fresh event must take its own TsNs — not leak
// the previous event's. Verifies the Feed-side body-drain reset.
func TestNextEventAfterBodyCompletesGetsItsOwnTsNs(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1234), int32(7)

	wire1 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	evA := makeEvent(events.SyscallWrite, pid, fd, uint32(len(wire1)), wire1)
	evA.TsNs = 100
	if got := p.Feed(evA); len(got) != 1 || got[0].TsNs != 100 {
		t.Fatalf("event A: want one event with TsNs=100, got %+v", got)
	}

	wire2 := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	evB := makeEvent(events.SyscallWrite, pid, fd, uint32(len(wire2)), wire2)
	evB.TsNs = 200
	got := p.Feed(evB)
	if len(got) != 1 || got[0].TsNs != 200 {
		t.Fatalf("event B: want one event with TsNs=200, got %+v", got)
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
			p := NewParser()
			// Buggy / weird origin: declares Content-Length but the status
			// forbids a body. Pair with a follow-up 200 to confirm framing.
			resp1 := []byte("HTTP/1.1 " + tc.status + "\r\nContent-Length: 1000\r\n\r\n")
			resp2 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			wire := append(append([]byte{}, resp1...), resp2...)
			got := p.Feed(makeEvent(events.SyscallWrite, 1234, 7, uint32(len(wire)), wire))
			if len(got) != 2 || got[0].Res.status != tc.code || got[1].Res.status != 200 {
				t.Fatalf("want [%d, 200], got %+v", tc.code, got)
			}
		})
	}
}
