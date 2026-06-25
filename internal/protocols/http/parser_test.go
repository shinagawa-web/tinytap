package http

import (
	"bytes"
	"fmt"
	"strings"
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

// --- Status code matrix ---------------------------------------------------

// Every 2xx/3xx/4xx/5xx status that carries a body is parsed with a
// non-zero Content-Length and a follow-up 200 to confirm framing closed.
func TestStatusCodeMatrix(t *testing.T) {
	cases := []struct {
		status  int
		hasBody bool
	}{
		{200, true},
		{201, true},
		{301, true},
		{302, true},
		{304, false}, // no body per RFC 7230 §3.3.3
		{400, true},
		{401, true},
		{403, true},
		{404, true},
		{500, true},
		{502, true},
		{503, true},
	}
	body := strings.Repeat("x", 7)
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%d", tc.status), func(t *testing.T) {
			p := NewParser()
			var resp1 []byte
			if tc.hasBody {
				resp1 = []byte(fmt.Sprintf("HTTP/1.1 %d Reason\r\nContent-Length: 7\r\n\r\n%s", tc.status, body))
			} else {
				resp1 = []byte(fmt.Sprintf("HTTP/1.1 %d Reason\r\nContent-Length: 7\r\n\r\n", tc.status))
			}
			resp2 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			wire := append(append([]byte{}, resp1...), resp2...)
			got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
			if len(got) != 2 {
				t.Fatalf("want 2 messages, got %d: %+v", len(got), got)
			}
			if got[0].Res.status != tc.status {
				t.Errorf("status: got %d, want %d", got[0].Res.status, tc.status)
			}
			if got[1].Res.status != 200 {
				t.Errorf("follow-up: got %d, want 200", got[1].Res.status)
			}
			if tc.hasBody && got[0].ContentLength != 7 {
				t.Errorf("status %d: ContentLength = %d, want 7", tc.status, got[0].ContentLength)
			}
			if !tc.hasBody && got[0].ContentLength != 0 {
				t.Errorf("status %d: ContentLength should be 0 (no-body), got %d", tc.status, got[0].ContentLength)
			}
		})
	}
}

// --- Method matrix --------------------------------------------------------

// All common request methods are parsed correctly. Non-HEAD responses keep
// their body framing — method tracking must not accidentally apply HEAD
// semantics to other verbs.
func TestMethodMatrix(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}
	for _, method := range methods {
		method := method
		t.Run(method, func(t *testing.T) {
			p := NewParser()
			pid, fd := uint32(1), int32(1)
			req := []byte(fmt.Sprintf("%s /path HTTP/1.1\r\nHost: x\r\n\r\n", method))
			got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(req)), req))
			if len(got) != 1 || !got[0].IsRequest || got[0].Req.method != method {
				t.Fatalf("request: want 1 %s event, got %+v", method, got)
			}
			resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
			got = p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(resp)), resp))
			if len(got) != 1 || got[0].ContentLength != 3 {
				t.Fatalf("%s response: want ContentLength=3, got %+v", method, got)
			}
		})
	}
}

// HEAD request paired with its response. The response must have no body
// even with Content-Length present.
func TestMethodHEAD(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)
	req := []byte("HEAD /file HTTP/1.1\r\nHost: x\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(req)), req))
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n")
	next := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	wire := append(append([]byte{}, resp...), next...)
	got := p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(wire)), wire))
	if len(got) != 2 {
		t.Fatalf("want [HEAD-resp, next-200], got %d: %+v", len(got), got)
	}
	if got[0].ContentLength != 0 {
		t.Errorf("HEAD response ContentLength should be 0, got %d", got[0].ContentLength)
	}
}

// --- Body-size boundaries -------------------------------------------------

// bodySizeTest feeds a response with the given body size as a single
// syscall (header + body together) and returns the emitted messages.
func feedBodySize(t *testing.T, bodySize int) []Message {
	t.Helper()
	body := bytes.Repeat([]byte("B"), bodySize)
	hdr := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", bodySize))
	wire := append(append([]byte{}, hdr...), body...)
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	return got
}

func TestBodySizeExactlySampleCap(t *testing.T) {
	got := feedBodySize(t, 256) // exactly MaxPayload
	if len(got) != 1 {
		t.Fatalf("want 1 message, got %d", len(got))
	}
	// headers consume most of the sample so body is likely truncated, but the
	// message is emitted and body size is correct on the wire.
	if got[0].ContentLength != 256 {
		t.Errorf("ContentLength = %d, want 256", got[0].ContentLength)
	}
}

func TestBodySizeOneOverSampleCap(t *testing.T) {
	got := feedBodySize(t, 257)
	if len(got) != 1 {
		t.Fatalf("want 1 message, got %d", len(got))
	}
	if got[0].ContentLength != 257 {
		t.Errorf("ContentLength = %d, want 257", got[0].ContentLength)
	}
}

func TestBodySizeTypicalHeaderLimit(t *testing.T) {
	// 8192 bytes — typical server header limit, body across many syscalls.
	p := NewParser()
	pid, fd := uint32(1), int32(1)
	const total = 8192
	hdr := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", total))
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(hdr)), hdr))
	var out []Message
	for sent := 0; sent < total; {
		n := 200
		if n > total-sent {
			n = total - sent
		}
		out = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(n), bytes.Repeat([]byte("x"), n)))
		sent += n
	}
	if len(out) != 1 || out[0].ContentLength != total {
		t.Fatalf("want 1 message with ContentLength=%d, got %+v", total, out)
	}
}

func TestBodySizeAbandonThresholdPlusOne(t *testing.T) {
	// 16 KiB + 1: body split across syscalls that each carry <=256 sample bytes.
	// This tests the multi-event drain path for very large bodies.
	p := NewParser()
	pid, fd := uint32(1), int32(1)
	const total = maxBodyBytes + 1
	hdr := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", total))
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(hdr)), hdr))
	var out []Message
	for sent := 0; sent < total; {
		n := 200
		if n > total-sent {
			n = total - sent
		}
		out = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(n), bytes.Repeat([]byte("z"), n)))
		sent += n
	}
	if len(out) != 1 || out[0].ContentLength != total {
		t.Fatalf("want 1 message with ContentLength=%d, got %+v", total, out)
	}
	if !out[0].BodyTruncated {
		t.Error("body > maxBodyBytes should be truncated")
	}
}

// Body arrives in a single syscall where wire bytes > body remaining — the
// debit cap is exercised inside Feed's stateNeedBody block.
func TestBodyDebitCap(t *testing.T) {
	// Response: Content-Length: 50, but the final syscall delivers 200 wire
	// bytes (body tail + a pipelined next message compressed in one event).
	p := NewParser()
	pid, fd := uint32(1), int32(1)
	hdr := []byte("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(hdr)), hdr))

	// First event: 30 of the 50 body bytes.
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, 30, bytes.Repeat([]byte("A"), 30)))

	// Second event: payload carries the last 20 body bytes plus the next message.
	// wire bytes == len(payload); the debit cap fires because bodyRemaining(20) <
	// wireBytes, not because wireBytes is inflated.
	next := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	tailBody := bytes.Repeat([]byte("B"), 20)
	payload := append(append([]byte{}, tailBody...), next...)
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(payload)), payload))
	// The 200-body message should complete on this event.
	statuses := make([]int, len(got))
	for i, m := range got {
		statuses[i] = m.Res.status
	}
	found200 := false
	for _, s := range statuses {
		if s == 200 {
			found200 = true
		}
	}
	if !found200 {
		t.Fatalf("want the 200 message to complete; got statuses=%v", statuses)
	}
}

// Body straddles the header boundary: the syscall carrying the headers also
// carries the first N bytes of the body; remaining bytes come in the next event.
func TestBodyStraddlesHeaderBoundary(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)
	// Single syscall: full headers + first 10 of 30 body bytes.
	partial := []byte("HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n" + strings.Repeat("A", 10))
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(partial)), partial))

	// Remaining 20 body bytes in the next syscall.
	rest := bytes.Repeat([]byte("B"), 20)
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, 20, rest))
	if len(got) != 1 || got[0].ContentLength != 30 {
		t.Fatalf("want 1 message with ContentLength=30, got %+v", got)
	}
}

// --- Malformed input ------------------------------------------------------

// Partial start-line: stream is closed before \r\n arrives — parser must
// not crash or emit spurious events.
func TestMalformedPartialStartLine(t *testing.T) {
	p := NewParser()
	p.Feed(makeEvent(events.SyscallWrite, 1, 1, 5, []byte("GET /")))
	p.Close(1, 1)
	// No assertion needed beyond "no panic" — the stream is evicted cleanly.
}

// Garbage bytes before HTTP: must abandon the stream (not crash, not emit).
func TestMalformedGarbageBeforeHTTP(t *testing.T) {
	p := NewParser()
	garbage := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 5)
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(garbage)), garbage))
	if len(got) != 0 {
		t.Fatalf("garbage input: want no events, got %+v", got)
	}
}

// Header line missing colon: the bad line is silently skipped; the message
// is still emitted and valid headers around it are preserved.
func TestMalformedHeaderMissingColon(t *testing.T) {
	p := NewParser()
	wire := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Bad-Header-No-Colon\r\nX-Good: yes\r\n\r\n")
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 1 || got[0].Res.status != 200 {
		t.Fatalf("want 1 message with status 200, got %+v", got)
	}
	// The bad header is dropped; X-Good must survive.
	found := false
	for _, h := range got[0].Headers {
		if h.Name == "X-Good" && h.Value == "yes" {
			found = true
		}
	}
	if !found {
		t.Errorf("X-Good header not found in %+v", got[0].Headers)
	}
}

// Oversized header block trips the maxBufBytes cap and marks the stream abandoned.
func TestMalformedOversizedHeaderTripsAbandoned(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)
	// Feed non-HTTP data past maxBufBytes in chunks to trigger the abandoned flag.
	// makeEvent truncates each chunk to events.MaxPayload bytes, so we need
	// ceil(maxBufBytes/events.MaxPayload)+1 events to reliably exceed the cap.
	chunk := bytes.Repeat([]byte("X"), events.MaxPayload)
	for i := 0; i < maxBufBytes/events.MaxPayload+1; i++ {
		p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(chunk)), chunk))
	}
	// Stream is now abandoned; further data must produce no events.
	valid := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(valid)), valid))
	if len(got) != 0 {
		t.Fatalf("abandoned stream: want no events after maxBufBytes, got %+v", got)
	}
}

// Content-Length with a non-numeric value is ignored (treated as zero).
func TestMalformedContentLengthNonNumeric(t *testing.T) {
	p := NewParser()
	wire := []byte("HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n")
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 1 || got[0].ContentLength != 0 {
		t.Fatalf("non-numeric CL: want ContentLength=0, got %+v", got)
	}
}

// Negative Content-Length is rejected; message is still emitted with zero body.
func TestMalformedContentLengthNegative(t *testing.T) {
	p := NewParser()
	wire := []byte("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n")
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 1 || got[0].ContentLength != 0 {
		t.Fatalf("negative CL: want ContentLength=0, got %+v", got)
	}
}

// Content-Length in hex is not a valid decimal integer; treated as zero.
func TestMalformedContentLengthHex(t *testing.T) {
	p := NewParser()
	wire := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0xFF\r\n\r\n")
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 1 || got[0].ContentLength != 0 {
		t.Fatalf("hex CL: want ContentLength=0, got %+v", got)
	}
}

// Malformed response start-line (not enough fields) causes the parser to
// give up on the stream without panicking.
func TestMalformedResponseStartLineTooFewFields(t *testing.T) {
	p := NewParser()
	wire := []byte("HTTP/1.1\r\n\r\n") // only one field, no status code
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 0 {
		t.Fatalf("malformed status line: want no events, got %+v", got)
	}
}

// Malformed response where status field is not a number.
func TestMalformedResponseStatusNotNumber(t *testing.T) {
	p := NewParser()
	wire := []byte("HTTP/1.1 TWO-HUNDRED OK\r\n\r\n")
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 0 {
		t.Fatalf("non-numeric status: want no events, got %+v", got)
	}
}

// Malformed request start-line (only two fields, no HTTP version).
func TestMalformedRequestStartLineTooFewFields(t *testing.T) {
	p := NewParser()
	wire := []byte("GET /path\r\n\r\n") // missing version
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 0 {
		t.Fatalf("malformed request line: want no events, got %+v", got)
	}
}

// Request line with no HTTP/ prefix in the third field is rejected.
func TestMalformedRequestNoHTTPVersion(t *testing.T) {
	p := NewParser()
	wire := []byte("GET /path GOPHER/1.0\r\n\r\n")
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 0 {
		t.Fatalf("non-HTTP version: want no events, got %+v", got)
	}
}

// --- Non-HTTP streams -----------------------------------------------------

// ELF magic followed by binary data: stream must be abandoned without events.
func TestNonHTTPELFMagic(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)
	elf := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	pad := bytes.Repeat([]byte{0x00}, 4096*5) // push past maxBufBytes
	wire := append(append([]byte{}, elf...), pad...)
	for i := 0; i < len(wire); i += 256 {
		end := i + 256
		if end > len(wire) {
			end = len(wire)
		}
		chunk := wire[i:end]
		got := p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(chunk)), chunk))
		if len(got) != 0 {
			t.Fatalf("ELF stream: unexpected event at offset %d: %+v", i, got)
		}
	}
}

// JSON-only stream (no HTTP envelope): must abandon cleanly.
func TestNonHTTPJSONOnly(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)
	// Enough JSON-ish data to exceed maxBufBytes without \r\n\r\n.
	json := bytes.Repeat([]byte(`{"key":"value","other":"data"}`), 600)
	for i := 0; i < len(json); i += 256 {
		end := i + 256
		if end > len(json) {
			end = len(json)
		}
		chunk := json[i:end]
		got := p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(chunk)), chunk))
		if len(got) != 0 {
			t.Fatalf("JSON stream: unexpected event at offset %d: %+v", i, got)
		}
	}
}

// Raw binary stream: same check.
func TestNonHTTPRawBinary(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)
	binary := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 4096*2)
	for i := 0; i < len(binary); i += 200 {
		end := i + 200
		if end > len(binary) {
			end = len(binary)
		}
		chunk := binary[i:end]
		p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(chunk)), chunk))
	}
	// After abandonment, a valid HTTP message on the same stream must be ignored.
	valid := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	got := p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(valid)), valid))
	if len(got) != 0 {
		t.Fatalf("abandoned binary stream: want no events, got %+v", got)
	}
}

// --- Stream lifecycle / Close ---------------------------------------------

// Close evicts both direction streams for the given (pid, fd).
func TestCloseEvictsStreams(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(42), int32(9)

	// Plant a partial message on the outgoing direction.
	partial := []byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(partial)), partial))

	// Plant a partial message on the incoming direction.
	req := []byte("POST /upload HTTP/1.1\r\nContent-Length: 50\r\n\r\n")
	p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(req)), req))

	if len(p.streams) == 0 {
		t.Fatal("expected streams to be populated before Close")
	}

	p.Close(pid, fd)

	// Both direction entries must be gone.
	if _, ok := p.streams[connKey{pid: pid, fd: fd, dir: dirIncoming}]; ok {
		t.Error("Close: incoming stream not evicted")
	}
	if _, ok := p.streams[connKey{pid: pid, fd: fd, dir: dirOutgoing}]; ok {
		t.Error("Close: outgoing stream not evicted")
	}
}

// Close evicts the pendingMethods queue for the given (pid, fd).
func TestCloseEvictsPendingMethods(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(42), int32(9)

	// Queue a request method.
	req := []byte("GET /foo HTTP/1.1\r\nHost: x\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(req)), req))

	if len(p.pendingMethods) == 0 {
		t.Fatal("expected pendingMethods to be populated before Close")
	}

	p.Close(pid, fd)

	if _, ok := p.pendingMethods[pidFd{pid: pid, fd: fd}]; ok {
		t.Error("Close: pendingMethods entry not evicted")
	}
}

// Closing an fd that was never used is a no-op (no panic).
func TestCloseUnknownFdIsNoop(t *testing.T) {
	p := NewParser()
	p.Close(999, 999) // must not panic
}

// After Close, feeding the same (pid, fd) starts a fresh stream.
func TestCloseAllowsReuseOfFd(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(5)

	req := []byte("GET /old HTTP/1.1\r\nHost: x\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(req)), req))
	p.Close(pid, fd)

	req2 := []byte("GET /new HTTP/1.1\r\nHost: x\r\n\r\n")
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(req2)), req2))
	if len(got) != 1 || got[0].Req.path != "/new" {
		t.Fatalf("after Close, want fresh /new request, got %+v", got)
	}
}

// Headers split across two events: the first event contains the start line
// and a partial header block (no \r\n\r\n yet). The parser must buffer and
// wait for the terminator rather than emitting a bogus message.
func TestHeadersSplitAcrossTwoEvents(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)

	// First event: start line + incomplete headers (no \r\n\r\n terminator).
	part1 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Foo: bar")
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(part1)), part1))
	if len(got) != 0 {
		t.Fatalf("partial headers: want no events yet, got %+v", got)
	}

	// Second event: terminator + body.
	part2 := []byte("\r\n\r\nhello")
	got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(part2)), part2))
	if len(got) != 1 || got[0].Res.status != 200 || string(got[0].BodySample) != "hello" {
		t.Fatalf("after header completion: want status=200 body=hello, got %+v", got)
	}
}

// --- Feed edge cases ------------------------------------------------------

// Event with Bytes == 0 produces no output.
func TestFeedZeroWireBytes(t *testing.T) {
	p := NewParser()
	e := makeEvent(events.SyscallWrite, 1, 1, 0, []byte("HTTP/1.1 200 OK\r\n\r\n"))
	e.Bytes = 0
	got := p.Feed(e)
	if len(got) != 0 {
		t.Fatalf("zero-wire-byte event: want no events, got %+v", got)
	}
}

// Unknown syscall type produces no output.
func TestFeedUnknownSyscall(t *testing.T) {
	p := NewParser()
	e := makeEvent(99, 1, 1, 10, []byte("HTTP/1.1 200 OK\r\n\r\n"))
	got := p.Feed(e)
	if len(got) != 0 {
		t.Fatalf("unknown syscall: want no events, got %+v", got)
	}
}

// All valid incoming syscall types are accepted.
func TestFeedIncomingSyscalls(t *testing.T) {
	wire := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	for _, sc := range []uint32{events.SyscallRead, events.SyscallRecvfrom, events.SyscallRecvmsg} {
		p := NewParser()
		got := p.Feed(makeEvent(sc, 1, 1, uint32(len(wire)), wire))
		if len(got) != 1 {
			t.Errorf("syscall %d: want 1 event, got %d", sc, len(got))
		}
	}
}

// All valid outgoing syscall types are accepted.
func TestFeedOutgoingSyscalls(t *testing.T) {
	wire := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	for _, sc := range []uint32{events.SyscallWrite, events.SyscallSendto, events.SyscallSendmsg} {
		p := NewParser()
		got := p.Feed(makeEvent(sc, 1, 1, uint32(len(wire)), wire))
		if len(got) != 1 {
			t.Errorf("syscall %d: want 1 event, got %d", sc, len(got))
		}
	}
}

// --- RenderMessage --------------------------------------------------------

func TestRenderMessageRequest(t *testing.T) {
	msg := Message{
		Pid:       123,
		Comm:      "curl",
		IsRequest: true,
		Req:       httpRequestLine{method: "GET", path: "/foo", version: "HTTP/1.1"},
	}
	out := RenderMessage(msg)
	if !strings.Contains(out, "request") || !strings.Contains(out, "GET") || !strings.Contains(out, "/foo") {
		t.Errorf("RenderMessage request: unexpected output %q", out)
	}
}

func TestRenderMessageResponse(t *testing.T) {
	msg := Message{
		Pid:       456,
		Comm:      "nginx",
		IsRequest: false,
		Res:       httpStatusLine{version: "HTTP/1.1", status: 200, reason: "OK"},
	}
	out := RenderMessage(msg)
	if !strings.Contains(out, "response") || !strings.Contains(out, "200") || !strings.Contains(out, "OK") {
		t.Errorf("RenderMessage response: unexpected output %q", out)
	}
}

// --- Defensive guard coverage --------------------------------------------

// Feed clamps PayloadLen to len(e.Payload) when the field exceeds the array
// size. This guard is unreachable via normal BPF events but must not panic.
func TestFeedPayloadLenExceedsArray(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	e := &events.Event{
		Pid:        1,
		Fd:         1,
		Bytes:      uint32(len(req)),
		PayloadLen: events.MaxPayload + 100, // beyond array bounds
		Syscall:    events.SyscallWrite,
	}
	copy(e.Payload[:], req)

	p := NewParser()
	_ = p.Feed(e) // must not panic
}

// When e.Bytes < e.PayloadLen the wire-byte count understates the payload.
// bodyAlready = wireBytesSinceMessageStart - wireBytesConsumed goes negative;
// the clamp at bodyAlready < 0 must hold it at zero.
func TestFeedWireBytesLessThanPayloadClampsBodyAlready(t *testing.T) {
	headers := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	e := &events.Event{
		Pid:        2,
		Fd:         2,
		Bytes:      3, // far fewer wire bytes than actual payload
		PayloadLen: uint32(len(headers)),
		Syscall:    events.SyscallWrite,
	}
	copy(e.Payload[:], headers)

	p := NewParser()
	_ = p.Feed(e) // must not panic; bodyAlready clamp applied
}

// advance returns immediately when the stream is in stateNeedBody.
// Body draining is Feed's responsibility; this branch is a defensive catch
// for internal-contract violations.
func TestAdvanceStateNeedBodyReturnsEmpty(t *testing.T) {
	p := NewParser()
	s := &stream{state: stateNeedBody, bodyRemaining: 100}
	msgs := p.advance(s, 1, "test", 0)
	if len(msgs) != 0 {
		t.Errorf("advance in stateNeedBody returned %d messages, want 0", len(msgs))
	}
}

// NewParserWithResolve wires a custom process-name resolver; when it returns
// a non-empty string that name is used instead of the BPF Comm field.
func TestNewParserWithResolve(t *testing.T) {
	resolved := "my-server"
	p := NewParserWithResolve(func(pid uint32) string { return resolved })

	wire := []byte("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
	ev := makeEvent(events.SyscallWrite, 42, 3, uint32(len(wire)), wire)
	copy(ev.Comm[:], "old-comm\x00")

	got := p.Feed(ev)
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	if got[0].Comm != resolved {
		t.Errorf("Comm = %q, want %q (resolver should override Comm field)", got[0].Comm, resolved)
	}
}

// --- Lifecycle: concurrent connections and isolation ----------------------

// One pid holding two fds simultaneously: each fd has an independent
// stream; messages on one fd must not affect the other.
func TestParserConcurrentFdsSamePid(t *testing.T) {
	p := NewParser()
	pid := uint32(42)
	fd4, fd5 := int32(4), int32(5)

	// Plant partial responses on both fds (no body yet → streams stay open).
	hdr := []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd4, uint32(len(hdr)), hdr))
	p.Feed(makeEvent(events.SyscallWrite, pid, fd5, uint32(len(hdr)), hdr))

	if _, ok := p.streams[connKey{pid: pid, fd: fd4, dir: dirOutgoing}]; !ok {
		t.Error("fd4 stream missing")
	}
	if _, ok := p.streams[connKey{pid: pid, fd: fd5, dir: dirOutgoing}]; !ok {
		t.Error("fd5 stream missing")
	}

	// Closing fd4 must leave fd5 intact.
	p.Close(pid, fd4)

	if _, ok := p.streams[connKey{pid: pid, fd: fd4, dir: dirOutgoing}]; ok {
		t.Error("fd4 stream should be evicted after Close")
	}
	if _, ok := p.streams[connKey{pid: pid, fd: fd5, dir: dirOutgoing}]; !ok {
		t.Error("fd5 stream should survive fd4 Close")
	}
}

// Two processes with the same fd number must be tracked independently.
// (42, fd=4) and (43, fd=4) are distinct connKey entries.
func TestParserSameFdDifferentPids(t *testing.T) {
	p := NewParser()
	fd := int32(4)
	pid42, pid43 := uint32(42), uint32(43)

	hdr := []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid42, fd, uint32(len(hdr)), hdr))
	p.Feed(makeEvent(events.SyscallWrite, pid43, fd, uint32(len(hdr)), hdr))

	if _, ok := p.streams[connKey{pid: pid42, fd: fd, dir: dirOutgoing}]; !ok {
		t.Error("pid42 stream missing")
	}
	if _, ok := p.streams[connKey{pid: pid43, fd: fd, dir: dirOutgoing}]; !ok {
		t.Error("pid43 stream missing")
	}

	// Closing one pid must not evict the other.
	p.Close(pid42, fd)

	if _, ok := p.streams[connKey{pid: pid42, fd: fd, dir: dirOutgoing}]; ok {
		t.Error("pid42 stream should be evicted after Close")
	}
	if _, ok := p.streams[connKey{pid: pid43, fd: fd, dir: dirOutgoing}]; !ok {
		t.Error("pid43 stream should survive pid42 Close")
	}
}

// 1000 keep-alive cycles: complete request + response + Close. Verifies
// that no entries remain in streams or pendingMethods after the burst.
func TestParserLeakSmokeTest(t *testing.T) {
	p := NewParser()
	pid := uint32(1)
	req := []byte("GET /x HTTP/1.1\r\nHost: x\r\n\r\n")
	res := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	for i := range 1000 {
		fd := int32(i % 10)
		p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(req)), req))
		p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(res)), res))
		p.Close(pid, fd)
	}

	if n := len(p.streams); n != 0 {
		t.Errorf("leak: %d stream entries remain after 1000 cycles", n)
	}
	if n := len(p.pendingMethods); n != 0 {
		t.Errorf("leak: %d pendingMethods entries remain after 1000 cycles", n)
	}
}

// --- Transfer-Encoding: chunked ------------------------------------------

// buildChunked assembles a valid chunked body from the given string chunks.
// The returned byte slice is: each chunk as "HEX\r\n<data>\r\n", then "0\r\n\r\n".
func buildChunked(chunks ...string) []byte {
	var b []byte
	for _, c := range chunks {
		b = append(b, []byte(fmt.Sprintf("%x\r\n%s\r\n", len(c), c))...)
	}
	b = append(b, []byte("0\r\n\r\n")...)
	return b
}

// Single-chunk chunked response delivered in one syscall.
func TestChunkedSingleChunk(t *testing.T) {
	body := buildChunked("hello")
	wire := append([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), body...)
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 1 || got[0].Res.status != 200 {
		t.Fatalf("want 1×200, got %+v", got)
	}
	if string(got[0].BodySample) != "hello" {
		t.Errorf("body = %q, want \"hello\"", got[0].BodySample)
	}
	if got[0].BodyTruncated {
		t.Error("small body must not be truncated")
	}
}

// Multiple chunks in one syscall — body is the concatenation of all chunks.
func TestChunkedMultipleChunks(t *testing.T) {
	body := buildChunked("foo", "bar", "baz")
	wire := append([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), body...)
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 1 {
		t.Fatalf("want 1 message, got %d", len(got))
	}
	if string(got[0].BodySample) != "foobarbaz" {
		t.Errorf("body = %q, want \"foobarbaz\"", got[0].BodySample)
	}
}

// Zero-length (empty) chunked body: "0\r\n\r\n" immediately after headers.
func TestChunkedEmptyBody(t *testing.T) {
	wire := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 1 || got[0].Res.status != 200 {
		t.Fatalf("want 1×200, got %+v", got)
	}
	if len(got[0].BodySample) != 0 {
		t.Errorf("empty chunked body: want 0 bytes, got %d", len(got[0].BodySample))
	}
}

// Chunk size line with an extension (";q=1") — the extension is stripped.
func TestChunkedChunkExtensionStripped(t *testing.T) {
	wire := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5;q=1\r\nhello\r\n0\r\n\r\n")
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 1 || string(got[0].BodySample) != "hello" {
		t.Fatalf("chunk extension: want body=\"hello\", got %+v", got)
	}
}

// Trailer header after the last chunk is accepted and consumed without crashing.
func TestChunkedTrailerHeader(t *testing.T) {
	wire := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n0\r\nX-Checksum: abc123\r\n\r\n")
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 1 || string(got[0].BodySample) != "hello" {
		t.Fatalf("trailer: want 1 message body=hello, got %+v", got)
	}
}

// Chunk boundary split across two syscalls: chunk data arrives in a second event.
func TestChunkedChunkSplitAcrossSyscalls(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)

	// First event: headers + chunk size line + first part of data.
	// "hello world" = 11 bytes = 0xb.
	part1 := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\nhello")
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(part1)), part1))
	if len(got) != 0 {
		t.Fatalf("mid-chunk: want no messages yet, got %+v", got)
	}

	// Second event: remainder of chunk data + CRLF + terminator.
	part2 := []byte(" world\r\n0\r\n\r\n")
	got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(part2)), part2))
	if len(got) != 1 || string(got[0].BodySample) != "hello world" {
		t.Fatalf("after completion: want body=\"hello world\", got %+v", got)
	}
}

// Large chunk that forces stateNeedChunkData wire-byte debiting across events.
func TestChunkedLargeChunkAcrossMultipleEvents(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)

	// Headers + chunk size for 1000 bytes.
	hdr := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3e8\r\n")
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(hdr)), hdr))
	if len(got) != 0 {
		t.Fatalf("headers+size: want 0 messages, got %d", len(got))
	}

	// Three events of 333 + 333 + 334 wire bytes.
	for i, n := range []int{333, 333, 334} {
		chunk := bytes.Repeat([]byte("X"), n)
		got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(n), chunk))
		if i < 2 && len(got) != 0 {
			t.Fatalf("chunk event %d: want 0 messages, got %d", i, len(got))
		}
	}

	// Final event: chunk CRLF + terminator.
	tail := []byte("\r\n0\r\n\r\n")
	got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(tail)), tail))
	if len(got) != 1 || got[0].Res.status != 200 {
		t.Fatalf("after terminator: want 1×200, got %+v", got)
	}
}

// Pipelined chunked response followed by a Content-Length response.
func TestChunkedFollowedByContentLengthResponse(t *testing.T) {
	body := buildChunked("hello")
	resp1 := append([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), body...)
	resp2 := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	wire := append(resp1, resp2...)
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 2 || got[0].Res.status != 200 || got[1].Res.status != 204 {
		t.Fatalf("want [200, 204], got %+v", got)
	}
}

// Chunked request body: POST with Transfer-Encoding: chunked.
func TestChunkedRequestBody(t *testing.T) {
	body := buildChunked(`{"name":"Alice"}`)
	wire := append([]byte("POST /users HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), body...)
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 1 || !got[0].IsRequest {
		t.Fatalf("want 1 request, got %+v", got)
	}
	if string(got[0].BodySample) != `{"name":"Alice"}` {
		t.Errorf("req body = %q, want json", got[0].BodySample)
	}
}

// Chunked response to a HEAD request: no body (RFC 7230 §3.3.3).
func TestChunkedHeadResponseHasNoBody(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)
	req := []byte("HEAD /file HTTP/1.1\r\nHost: x\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(req)), req))

	// HEAD response with Transfer-Encoding but no body.
	resp := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	next := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	wire := append(resp, next...)
	got := p.Feed(makeEvent(events.SyscallRead, pid, fd, uint32(len(wire)), wire))
	if len(got) != 2 || got[0].Res.status != 200 || got[1].Res.status != 204 {
		t.Fatalf("HEAD+chunked: want [200, 204], got %+v", got)
	}
}

// Malformed chunk size (non-hex characters) causes the stream to be abandoned.
func TestChunkedMalformedChunkSizeAbandonsStream(t *testing.T) {
	wire := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\nhello\r\n0\r\n\r\n")
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 0 {
		t.Fatalf("malformed chunk size: want no events, got %+v", got)
	}
	// Further data on the same stream must be ignored.
	next := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	got = p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(next)), next))
	if len(got) != 0 {
		t.Fatalf("after malformed chunk: abandoned stream should emit nothing, got %+v", got)
	}
}

// Malformed chunk terminator (not "\r\n") causes the stream to be abandoned.
func TestChunkedMalformedChunkCRLFAbandonsStream(t *testing.T) {
	// Chunk size says 5, data is "hello", but terminator is "\n\n" not "\r\n".
	wire := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\n\n0\r\n\r\n")
	p := NewParser()
	got := p.Feed(makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire))
	if len(got) != 0 {
		t.Fatalf("malformed CRLF: want no events, got %+v", got)
	}
}

// Chunked body truncated by the sample cap: large chunk data beyond MaxPayload
// is flagged as truncated.
func TestChunkedBodyTruncatedBySampleCap(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)

	// Headers + chunk size for 500 bytes.
	hdr := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1f4\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(hdr)), hdr))

	// Single event: 500 wire bytes but sample capped at MaxPayload (256).
	body := bytes.Repeat([]byte("X"), 500)
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, 500, body[:256]))
	if len(got) != 0 {
		t.Fatalf("mid-chunk (500 wire, 256 sample): want 0 messages, got %d", len(got))
	}

	// Terminator arrives in the next event.
	tail := []byte("\r\n0\r\n\r\n")
	got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(tail)), tail))
	if len(got) != 1 {
		t.Fatalf("want 1 message after terminator, got %d", len(got))
	}
	if !got[0].BodyTruncated {
		t.Error("chunked body larger than sample cap must be truncated")
	}
}

// --- Chunked edge cases (defensive guards and split framing) ---------------

// Chunk-size line split across two syscalls: "\r\n" arrives in the second event.
// Covers the stateNeedChunkSize idx < 0 guard.
func TestChunkedChunkSizeLineSplitAcrossSyscalls(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)

	// First event: headers + "5" (partial chunk-size, no \r\n yet).
	part1 := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5")
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(part1)), part1))
	if len(got) != 0 {
		t.Fatalf("partial chunk-size line: want 0 messages, got %+v", got)
	}

	// Second event: "\r\nhello\r\n0\r\n\r\n" completes the chunk.
	part2 := []byte("\r\nhello\r\n0\r\n\r\n")
	got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(part2)), part2))
	if len(got) != 1 || string(got[0].BodySample) != "hello" {
		t.Fatalf("after chunk-size completion: want body=\"hello\", got %+v", got)
	}
}

// All chunk wire bytes arrived in one oversized syscall, sample too short.
// Covers bodyTruncated in the chunkDataArrived >= chunkSize branch (line 656)
// and the stateNeedChunkCRLF len < 2 guard (line 677).
func TestChunkedAllWireBytesArrivedSampleTooShort(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)

	// Event 1: headers alone (fully sampled).
	hdr := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(hdr)), hdr))

	// Event 2: chunk size "1f4\r\n" (5 bytes) + 500 bytes of data, but sample
	// is capped at 256 — so chunkDataArrived (500) >= chunkSize (500) but
	// bodyInBuf (251) < chunkSize (500), triggering the truncation flag.
	// After consuming all sample bytes the buf is empty, so stateNeedChunkCRLF
	// fires the len < 2 guard and returns immediately.
	chunkHdr := []byte("1f4\r\n")
	body := bytes.Repeat([]byte("X"), 500)
	sample := append(chunkHdr, body[:251]...) // 256 bytes total sample
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(chunkHdr)+len(body)), sample))
	if len(got) != 0 {
		t.Fatalf("mid-chunk: want 0 messages, got %d", len(got))
	}

	// Event 3: CRLF after chunk + terminating chunk.
	tail := []byte("\r\n0\r\n\r\n")
	got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(tail)), tail))
	if len(got) != 1 {
		t.Fatalf("after terminator: want 1 message, got %d", len(got))
	}
	if !got[0].BodyTruncated {
		t.Error("body must be truncated when sample < chunk wire size")
	}
}

// Chunk partially arrived and wire bytes of chunk exceed sample bytes.
// Covers bodyTruncated in the chunkDataArrived < chunkSize else-branch (line 665).
func TestChunkedPartialChunkWireExceedsSample(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)

	// Event 1: headers alone.
	hdr := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(hdr)), hdr))

	// Event 2: chunk size "3e8\r\n" (1000 bytes) + 200 wire bytes of data, but
	// sample carries only chunk-size bytes + 95 data bytes (100 total).
	// chunkDataArrived = 200, chunkSize = 1000, bodyInBuf = 95.
	// Since 200 > 95, bodyTruncated is set in the else branch.
	chunkHdr := []byte("3e8\r\n")
	data := bytes.Repeat([]byte("Y"), 200)
	sample := append(chunkHdr, data[:95]...) // 100 bytes total sample
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, 205, sample))
	if len(got) != 0 {
		t.Fatalf("mid-large-chunk: want 0 messages, got %d", len(got))
	}

	// Drain the remaining 800 wire bytes across further events.
	remaining := 1000 - 200
	chunk := bytes.Repeat([]byte("Z"), 200)
	for remaining > 0 {
		n := 200
		if n > remaining {
			n = remaining
		}
		got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(n), chunk[:n]))
		remaining -= n
	}

	// Terminator.
	tail := []byte("\r\n0\r\n\r\n")
	got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(tail)), tail))
	if len(got) != 1 {
		t.Fatalf("after terminator: want 1 message, got %d", len(got))
	}
	if !got[0].BodyTruncated {
		t.Error("body must be truncated when wire bytes of partial chunk exceed sample bytes")
	}
}

// Trailer section split across two syscalls.
// Covers the stateNeedTrailer tidx < 0 guard (line 699).
func TestChunkedTrailerSplitAcrossSyscalls(t *testing.T) {
	p := NewParser()
	pid, fd := uint32(1), int32(1)

	// Event 1: headers + chunk + zero-chunk + partial trailer (no final \r\n).
	// "X-Chk: abc\r\n" arrives but the closing empty line does not.
	part1 := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n0\r\nX-Chk: abc\r\n")
	got := p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(part1)), part1))
	if len(got) != 0 {
		t.Fatalf("partial trailer: want 0 messages, got %+v", got)
	}

	// Event 2: closing empty line completes the trailer section.
	part2 := []byte("\r\n")
	got = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(part2)), part2))
	if len(got) != 1 || string(got[0].BodySample) != "hello" {
		t.Fatalf("after trailer completion: want body=\"hello\", got %+v", got)
	}
}

// Understated Bytes field in the BPF event causes chunkDataArrived to go
// negative inside stateNeedChunkSize; the clamp must hold it at zero.
// Mirrors TestFeedWireBytesLessThanPayloadClampsBodyAlready for chunked paths.
func TestChunkedWireBytesUnderstatedClampsChunkDataArrived(t *testing.T) {
	// Headers + chunk-size line fit in the payload but Bytes is set to 3,
	// far less than the actual byte count. After headers are consumed,
	// wireBytesConsumed > wireBytesSinceMessageStart, so chunkDataArrived < 0.
	hdr := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n"
	e := &events.Event{
		Pid:        1,
		Fd:         1,
		Bytes:      3, // severely understated
		PayloadLen: uint32(len(hdr)),
		Syscall:    events.SyscallWrite,
	}
	copy(e.Payload[:], hdr)

	p := NewParser()
	_ = p.Feed(e) // must not panic; chunkDataArrived clamp applied
}

// Understated Bytes field causes carryOver to go negative inside stateNeedTrailer;
// the clamp must hold it at zero and the message must still be emitted.
func TestChunkedWireBytesUnderstatedClampsCarryOver(t *testing.T) {
	// Complete minimal chunked response in one payload, but Bytes = 5.
	// wireBytesConsumed races past wireBytesSinceMessageStart, so
	// carryOver = wireBytesSinceMessageStart - wireBytesConsumed < 0.
	payload := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
	e := &events.Event{
		Pid:        2,
		Fd:         2,
		Bytes:      5, // understated
		PayloadLen: uint32(len(payload)),
		Syscall:    events.SyscallWrite,
	}
	copy(e.Payload[:], payload)

	p := NewParser()
	got := p.Feed(e) // must not panic; carryOver clamp applied
	if len(got) != 1 || got[0].Res.status != 200 {
		t.Fatalf("understated Bytes + empty chunked body: want 1×200, got %+v", got)
	}
}

// TsNs for a pipelined message after a chunked response uses the correct event ts.
func TestChunkedPipelinedTsNs(t *testing.T) {
	body := buildChunked("hello")
	resp1 := append([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), body...)
	resp2 := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	wire := append(resp1, resp2...)
	p := NewParser()
	ev := makeEvent(events.SyscallWrite, 1, 1, uint32(len(wire)), wire)
	ev.TsNs = 99_000_000_000
	got := p.Feed(ev)
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
	if got[0].TsNs != 99_000_000_000 || got[1].TsNs != 99_000_000_000 {
		t.Errorf("TsNs: got [%d, %d], want both 99_000_000_000", got[0].TsNs, got[1].TsNs)
	}
}
