package http

import (
	"fmt"
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

	// Event 1: headers + first 1000 wire bytes of body, sample 256. The message
	// is now emitted only once the body fully drains (#35), so nothing comes
	// out while the body is still arriving.
	ev1Wire := append(append([]byte{}, headers...), chunk...)
	ev1 := makeEvent(events.SyscallWrite, pid, fd, uint32(len(headers)+len(chunk)), ev1Wire)
	if got := p.Feed(ev1); len(got) != 0 {
		t.Fatalf("event 1: expected no HTTP events while body drains, got %+v", got)
	}

	// Event 2: 1000 more wire bytes of body — still draining.
	ev2 := makeEvent(events.SyscallWrite, pid, fd, uint32(len(chunk)), chunk)
	if got := p.Feed(ev2); len(got) != 0 {
		t.Fatalf("event 2: expected no HTTP events while body drains, got %+v", got)
	}

	// Event 3: final 1000 wire bytes — body complete (3000), message emitted.
	// Each syscall carried 1000 wire bytes but only 256 sample bytes, so the
	// body is captured partially and flagged truncated.
	ev3 := makeEvent(events.SyscallWrite, pid, fd, uint32(len(chunk)), chunk)
	got := p.Feed(ev3)
	if len(got) != 1 || got[0].Res.status != 200 {
		t.Fatalf("event 3: want 1 event with status 200 at body completion, got %+v", got)
	}
	if !got[0].BodyTruncated {
		t.Error("body delivered in >MaxPayload syscalls should be truncated")
	}
	if len(got[0].BodySample) == 0 || len(got[0].BodySample) >= 3000 {
		t.Errorf("want a partial body sample (0 < n < 3000), got %d bytes", len(got[0].BodySample))
	}

	// Event 4: next pipelined response — only parses if body framing closed.
	next := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	ev4 := makeEvent(events.SyscallWrite, pid, fd, uint32(len(next)), next)
	if got := p.Feed(ev4); len(got) != 1 || got[0].Res.status != 204 {
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

// The parser keeps every header in wire order, preserves unknown/custom
// headers (not just Content-Length), and trims surrounding whitespace from
// both name and value. Continuation/obs-fold lines are out of scope (#34).
func TestParserPreservesHeaders(t *testing.T) {
	p := NewParser()
	req := "GET /api HTTP/1.1\r\n" +
		"Host: localhost:8081\r\n" +
		"User-Agent:   curl/8.14.1  \r\n" + // padded value must be trimmed
		"X-Custom-Trace: abc123\r\n" +
		"Accept: */*\r\n" +
		"\r\n"
	got := p.Feed(makeEvent(events.SyscallWrite, 1234, 7, uint32(len(req)), []byte(req)))
	if len(got) != 1 {
		t.Fatalf("Feed returned %d messages, want 1", len(got))
	}
	want := []Header{
		{Name: "Host", Value: "localhost:8081"},
		{Name: "User-Agent", Value: "curl/8.14.1"},
		{Name: "X-Custom-Trace", Value: "abc123"},
		{Name: "Accept", Value: "*/*"},
	}
	if len(got[0].Headers) != len(want) {
		t.Fatalf("got %d headers, want %d: %+v", len(got[0].Headers), len(want), got[0].Headers)
	}
	for i, h := range want {
		if got[0].Headers[i] != h {
			t.Errorf("header[%d] = %+v, want %+v", i, got[0].Headers[i], h)
		}
	}
}

// A message with no header lines (e.g. "HTTP/1.1 204 No Content\r\n\r\n")
// yields an empty header slice, not a crash or a phantom entry.
func TestParserZeroHeaders(t *testing.T) {
	p := NewParser()
	wire := "HTTP/1.1 204 No Content\r\n\r\n"
	got := p.Feed(makeEvent(events.SyscallRead, 1234, 7, uint32(len(wire)), []byte(wire)))
	if len(got) != 1 {
		t.Fatalf("Feed returned %d messages, want 1", len(got))
	}
	if len(got[0].Headers) != 0 {
		t.Errorf("want no headers, got %+v", got[0].Headers)
	}
}

// A body that fits in one syscall within the sample cap is retained in full and
// not flagged truncated.
func TestBodyFullyCapturedInOneSyscall(t *testing.T) {
	body := "hello world"
	wire := []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n" + body)
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1234, 7, uint32(len(wire)), wire))
	if len(got) != 1 {
		t.Fatalf("want 1 message, got %d", len(got))
	}
	if string(got[0].BodySample) != body || got[0].BodyTruncated {
		t.Errorf("body = %q truncated=%v, want %q false", got[0].BodySample, got[0].BodyTruncated, body)
	}
}

// A request (POST) body is captured too, not just responses.
func TestRequestBodyCaptured(t *testing.T) {
	body := `{"name":"Alice"}`
	wire := []byte("POST /users HTTP/1.1\r\nContent-Length: 16\r\n\r\n" + body)
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1234, 7, uint32(len(wire)), wire))
	if len(got) != 1 || !got[0].IsRequest {
		t.Fatalf("want 1 request message, got %+v", got)
	}
	if string(got[0].BodySample) != body || got[0].BodyTruncated {
		t.Errorf("req body = %q truncated=%v, want %q false", got[0].BodySample, got[0].BodyTruncated, body)
	}
}

// Binary body bytes are captured verbatim (the hex/decoded split is the TUI's
// job, not the parser's).
func TestBinaryBodyCapturedVerbatim(t *testing.T) {
	body := []byte{0x00, 0x01, 0x7f, 0xff, 'A', 0x0a}
	hdr := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
	wire := append([]byte(hdr), body...)
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1234, 7, uint32(len(wire)), wire))
	if len(got) != 1 {
		t.Fatalf("want 1 message, got %d", len(got))
	}
	if string(got[0].BodySample) != string(body) {
		t.Errorf("body = %v, want %v", got[0].BodySample, body)
	}
}

// A single syscall larger than the sample cap keeps only the sampled prefix and
// flags the body truncated. Headers arrive alone first so the cap applies to
// the body, not to headers + body sharing one sample.
func TestBodyInOneLargeSyscallTruncatedToSample(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1234), int32(7)
	hdr := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
	if got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(hdr)), hdr)); len(got) != 0 {
		t.Fatalf("headers alone should not emit yet, got %+v", got)
	}
	body := make([]byte, 1000)
	for i := range body {
		body[i] = 'B'
	}
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, 1000, body))
	if len(got) != 1 {
		t.Fatalf("want 1 message at body completion, got %d", len(got))
	}
	if !got[0].BodyTruncated {
		t.Error("a body larger than the sample cap should be truncated")
	}
	if n := len(got[0].BodySample); n == 0 || n > 256 {
		t.Errorf("want a sample-capped body (0 < n <= 256), got %d", n)
	}
}

// A body spread over several syscalls, each within the sample cap, is retained
// in full and not flagged truncated.
func TestBodyAcrossSmallSyscallsFullyRetained(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1234), int32(7)
	hdr := []byte("HTTP/1.1 200 OK\r\nContent-Length: 600\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(hdr)), hdr))
	var sent []byte
	for c := 0; c < 3; c++ {
		chunk := make([]byte, 200) // <= 256, fully sampled
		for i := range chunk {
			chunk[i] = byte('A' + c)
		}
		sent = append(sent, chunk...)
		got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, 200, chunk))
		if c < 2 {
			if len(got) != 0 {
				t.Fatalf("chunk %d: should still be draining, got %+v", c, got)
			}
			continue
		}
		if len(got) != 1 {
			t.Fatalf("final chunk: want 1 message, got %d", len(got))
		}
		if got[0].BodyTruncated {
			t.Error("a body fully captured across small syscalls should not be truncated")
		}
		if string(got[0].BodySample) != string(sent) {
			t.Errorf("body = %q, want %q", got[0].BodySample, sent)
		}
	}
}

// A body exceeding the per-message budget retains exactly maxBodyBytes and is
// flagged truncated.
func TestBodyPerMessageBudget(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1234), int32(7)
	total := maxBodyBytes + 5000
	hdr := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", total))
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(hdr)), hdr))
	var got []Message
	for remaining := total; remaining > 0; {
		n := 200 // each chunk fully sampled, so the cap is the only truncation
		if n > remaining {
			n = remaining
		}
		got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(n), make([]byte, n)))
		remaining -= n
	}
	if len(got) != 1 {
		t.Fatalf("want 1 message at completion, got %d", len(got))
	}
	if !got[0].BodyTruncated {
		t.Error("a body exceeding maxBodyBytes should be truncated")
	}
	if len(got[0].BodySample) != maxBodyBytes {
		t.Errorf("retained %d bytes, want the cap %d", len(got[0].BodySample), maxBodyBytes)
	}
}
