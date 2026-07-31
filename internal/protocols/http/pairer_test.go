package http

import (
	"testing"
	"time"
)

func TestPairerMatchesRequestAndResponse(t *testing.T) {
	p := NewPairer()

	reqTs := uint64(1_000_000_000)
	resTs := uint64(1_001_500_000) // +1.5ms

	req := Message{
		TsNs: reqTs, Pid: 42, Fd: 7, Comm: "curl", IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/x", version: "HTTP/1.1"},
	}
	res := Message{
		TsNs: resTs, Pid: 42, Fd: 7, Comm: "python3", IsRequest: false,
		Res:           httpStatusLine{version: "HTTP/1.1", status: 200, reason: "OK"},
		ContentLength: 649,
	}

	if pe, ok := p.Push(req); ok {
		t.Fatalf("request alone must not pair, got %+v", pe)
	}
	pe, ok := p.Push(res)
	if !ok {
		t.Fatalf("response should pair with queued request")
	}
	if pe.Method != "GET" || pe.Path != "/x" || pe.Status != 200 || pe.ResBytes != 649 {
		t.Errorf("paired fields: %+v", pe)
	}
	if pe.Latency != 1500*time.Microsecond {
		t.Errorf("want 1.5ms latency, got %v", pe.Latency)
	}
	// Queue should be empty now.
	if len(p.pending) != 0 {
		t.Errorf("pending should be empty, got %+v", p.pending)
	}
}

// HTTP/1.1 pipelining: two requests on the same (pid, fd), then two
// responses in order. The pairer must match by FIFO arrival.
func TestPairerHandlesPipelining(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(42), int32(7)

	r1 := Message{TsNs: 100, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/a"}}
	r2 := Message{TsNs: 200, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/b"}}
	s1 := Message{TsNs: 300, Pid: pid, Fd: fd, IsRequest: false,
		Res: httpStatusLine{status: 200}}
	s2 := Message{TsNs: 400, Pid: pid, Fd: fd, IsRequest: false,
		Res: httpStatusLine{status: 204}}

	p.Push(r1)
	p.Push(r2)

	pe1, ok := p.Push(s1)
	if !ok || pe1.Path != "/a" || pe1.Status != 200 {
		t.Errorf("first pair: %+v ok=%v", pe1, ok)
	}
	pe2, ok := p.Push(s2)
	if !ok || pe2.Path != "/b" || pe2.Status != 204 {
		t.Errorf("second pair: %+v ok=%v", pe2, ok)
	}
}

// A response with no queued request never pairs on its own Push call — it
// is held (#67) rather than paired or dropped outright, in case a matching
// request shows up later. See TestPairerHeldResponsesAreBounded for the
// case where no request ever arrives.
func TestPairerOrphanResponseDoesNotPairImmediately(t *testing.T) {
	p := NewPairer()
	res := Message{TsNs: 100, Pid: 42, Fd: 7, IsRequest: false,
		Res: httpStatusLine{status: 200}}
	if pe, ok := p.Push(res); ok {
		t.Errorf("orphan response should not pair immediately, got %+v", pe)
	}
}

// #67: an early response — e.g. a 413/417 error or a 100-continue reply —
// can arrive before the request Message is emitted, since the request is
// only emitted once its body fully drains (approach A). The pairer must
// hold the response and pair it once the matching request shows up, rather
// than dropping it.
func TestPairerPairsResponseThatArrivesBeforeRequest(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(42), int32(7)

	res := Message{TsNs: 100, Pid: pid, Fd: fd, IsRequest: false,
		Res: httpStatusLine{status: 413, reason: "Payload Too Large"}}
	if pe, ok := p.Push(res); ok {
		t.Fatalf("response with no queued request must not pair immediately, got %+v", pe)
	}

	// The request (large upload) only finishes streaming, and is only
	// emitted, after the early error response already arrived.
	req := Message{TsNs: 50, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "POST", path: "/upload", version: "HTTP/1.1"}}
	pe, ok := p.Push(req)
	if !ok {
		t.Fatal("request must pair with the held response")
	}
	if pe.Method != "POST" || pe.Path != "/upload" || pe.Status != 413 {
		t.Errorf("paired fields: %+v", pe)
	}
	if pe.Latency != 50 {
		t.Errorf("Latency = %v, want 50ns (res.TsNs - req.TsNs)", pe.Latency)
	}
}

// Two early responses on the same identity must pair FIFO: the oldest held
// response claims the first request that shows up, mirroring the in-order
// pipelining guarantee (TestPairerHandlesPipelining).
func TestPairerHeldResponsesPairInFIFOOrder(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(42), int32(7)

	p.Push(Message{TsNs: 1, Pid: pid, Fd: fd, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	p.Push(Message{TsNs: 2, Pid: pid, Fd: fd, IsRequest: false,
		Res: httpStatusLine{status: 204}})

	pe1, ok := p.Push(Message{TsNs: 3, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/a"}})
	if !ok || pe1.Path != "/a" || pe1.Status != 200 {
		t.Errorf("first request should claim the oldest held response: %+v ok=%v", pe1, ok)
	}
	pe2, ok := p.Push(Message{TsNs: 4, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/b"}})
	if !ok || pe2.Path != "/b" || pe2.Status != 204 {
		t.Errorf("second request should claim the next held response: %+v ok=%v", pe2, ok)
	}
}

// A flood of orphan responses — ones whose request was never captured at
// all — must not grow heldResponses without bound.
func TestPairerHeldResponsesAreBounded(t *testing.T) {
	p := NewPairer()
	pid := uint32(42)

	for i := 0; i < maxHeldResponses+50; i++ {
		p.Push(Message{TsNs: uint64(i), Pid: pid, Fd: int32(i), IsRequest: false,
			Res: httpStatusLine{status: 200}})
	}
	if len(p.heldResponses) != maxHeldResponses {
		t.Errorf("heldResponses = %d, want capped at %d", len(p.heldResponses), maxHeldResponses)
	}

	// The oldest held responses (fd=0..49) must have been evicted; a
	// request on fd=0 now finds nothing waiting and is queued instead.
	if _, ok := p.Push(Message{TsNs: 1000, Pid: pid, Fd: 0, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/evicted"}}); ok {
		t.Error("request on an evicted held response's key must not pair")
	}
}

// Once Close evicts a connection, any response it held must go with it —
// otherwise a later, unrelated request that reuses the same (pid, fd) could
// wrongly claim a response left over from the previous connection.
func TestPairerCloseDiscardsHeldResponse(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(42), int32(7)

	p.Push(Message{TsNs: 1, Pid: pid, Fd: fd, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	p.Close(pid, fd, 2)

	// A new, unrelated request reusing the same (pid, fd) must not pair
	// with the stale held response from the closed connection.
	if pe, ok := p.Push(Message{TsNs: 3, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/new"}}); ok {
		t.Errorf("request must not pair with a held response from a closed connection, got %+v", pe)
	}
}

// CloseSSL must discard a held response on its SSLFallback identity for the
// same reason Close does on fd-keyed identities (#173's SSL*-keyed mirror
// of TestPairerCloseDiscardsHeldResponse).
func TestPairerCloseSSLDiscardsHeldResponse(t *testing.T) {
	p := NewPairer()
	pid, ssl := uint32(42), uint64(0x1000)

	p.Push(Message{TsNs: 1, Pid: pid, SSL: ssl, SSLFallback: true, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	p.CloseSSL(pid, ssl, 2)

	if pe, ok := p.Push(Message{TsNs: 3, Pid: pid, SSL: ssl, SSLFallback: true, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/new"}}); ok {
		t.Errorf("request must not pair with a held response from a closed SSL connection, got %+v", pe)
	}
}

// Close/CloseSSL must only discard held responses on their own key — an
// unrelated connection's held response must survive.
func TestPairerCloseOnlyDiscardsOwnHeldResponse(t *testing.T) {
	p := NewPairer()
	pid := uint32(42)
	fdA, fdB := int32(7), int32(8)

	p.Push(Message{TsNs: 1, Pid: pid, Fd: fdA, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	p.Push(Message{TsNs: 2, Pid: pid, Fd: fdB, IsRequest: false,
		Res: httpStatusLine{status: 201}})

	p.Close(pid, fdA, 3)

	pe, ok := p.Push(Message{TsNs: 4, Pid: pid, Fd: fdB, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/b"}})
	if !ok || pe.Status != 201 {
		t.Errorf("fdB's held response must survive fdA's Close: %+v ok=%v", pe, ok)
	}
}

// The pairer carries request and response headers into the PairedEvent
// without dropping or reordering them.
func TestPairerCarriesHeaders(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(42), int32(7)
	req := Message{TsNs: 100, Pid: pid, Fd: fd, IsRequest: true,
		Headers: []Header{{Name: "Host", Value: "x"}, {Name: "Accept", Value: "*/*"}}}
	res := Message{TsNs: 200, Pid: pid, Fd: fd, IsRequest: false,
		Res:     httpStatusLine{status: 200},
		Headers: []Header{{Name: "Content-Type", Value: "application/json"}}}
	if _, ok := p.Push(req); ok {
		t.Fatal("request should be queued, not paired")
	}
	pe, ok := p.Push(res)
	if !ok {
		t.Fatal("response should pair with the queued request")
	}
	if len(pe.ReqHeaders) != 2 || pe.ReqHeaders[0].Name != "Host" || pe.ReqHeaders[1].Name != "Accept" {
		t.Errorf("ReqHeaders = %+v, want [Host Accept] in order", pe.ReqHeaders)
	}
	if len(pe.ResHeaders) != 1 || pe.ResHeaders[0].Name != "Content-Type" {
		t.Errorf("ResHeaders = %+v, want [Content-Type]", pe.ResHeaders)
	}
}

// The pairer carries request and response bodies (and their truncation flags)
// into the PairedEvent. A POST populates both; a body-less request leaves
// ReqBody empty.
func TestPairerCarriesBodies(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(42), int32(7)
	req := Message{TsNs: 100, Pid: pid, Fd: fd, IsRequest: true,
		ContentLength: 5, BodySample: []byte("hello")}
	res := Message{TsNs: 200, Pid: pid, Fd: fd, IsRequest: false,
		Res: httpStatusLine{status: 200}, ContentLength: 4,
		BodySample: []byte("body"), BodyTruncated: true}
	if _, ok := p.Push(req); ok {
		t.Fatal("request should be queued, not paired")
	}
	pe, ok := p.Push(res)
	if !ok {
		t.Fatal("response should pair with the queued request")
	}
	if string(pe.ReqBody) != "hello" || pe.ReqBodyTruncated {
		t.Errorf("ReqBody = %q trunc=%v, want \"hello\" false", pe.ReqBody, pe.ReqBodyTruncated)
	}
	if string(pe.ResBody) != "body" || !pe.ResBodyTruncated {
		t.Errorf("ResBody = %q trunc=%v, want \"body\" true", pe.ResBody, pe.ResBodyTruncated)
	}
	if pe.ReqBytes != 5 || pe.ResBytes != 4 {
		t.Errorf("ReqBytes=%d ResBytes=%d, want 5 and 4", pe.ReqBytes, pe.ResBytes)
	}
}

// For chunked responses, ContentLength is zero (no Content-Length header), so
// ResBytes must fall back to len(BodySample) to reflect the sampled body size.
func TestPairerChunkedResBytes(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(10), int32(5)
	req := Message{TsNs: 1, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/", version: "HTTP/1.1"}}
	// ContentLength == 0 mimics a chunked response (no Content-Length header).
	res := Message{TsNs: 2, Pid: pid, Fd: fd, IsRequest: false,
		Res:           httpStatusLine{status: 200},
		ContentLength: 0,
		BodySample:    []byte("Hello chunked world!")}
	p.Push(req)
	pe, ok := p.Push(res)
	if !ok {
		t.Fatal("want paired event")
	}
	if pe.ResBytes != 20 {
		t.Errorf("ResBytes = %d, want 20 (len of chunked body sample)", pe.ResBytes)
	}
}

// Close returns an abandoned PairedEvent for each pending request and removes
// them; a response arriving after Close must not pair.
func TestPairerCloseEmitsAbandoned(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(7), int32(3)

	req := Message{TsNs: 100, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/x", version: "HTTP/1.1"}}
	p.Push(req)

	abandoned := p.Close(pid, fd, 200)
	if len(abandoned) != 1 {
		t.Fatalf("want 1 abandoned event, got %d", len(abandoned))
	}
	ab := abandoned[0]
	if !ab.Abandoned {
		t.Error("Abandoned must be true")
	}
	if ab.AbandonReason != AbandonReasonClosed {
		t.Errorf("AbandonReason = %q, want %q", ab.AbandonReason, AbandonReasonClosed)
	}
	if ab.Method != "GET" || ab.Path != "/x" {
		t.Errorf("method/path = %q %q, want GET /x", ab.Method, ab.Path)
	}
	if ab.Latency != 100 {
		t.Errorf("Latency = %v, want 100ns (closeTsNs - reqTsNs)", ab.Latency)
	}

	res := Message{TsNs: 300, Pid: pid, Fd: fd, IsRequest: false,
		Res: httpStatusLine{version: "HTTP/1.1", status: 200, reason: "OK"}}
	if _, ok := p.Push(res); ok {
		t.Error("response after Close should not pair with the evicted request")
	}
}

// Close with two pipelined requests emits two abandoned events in FIFO order.
func TestPairerClosePipeliningAbandoned(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(7), int32(3)

	p.Push(Message{TsNs: 1, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/a"}})
	p.Push(Message{TsNs: 2, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/b"}})

	abandoned := p.Close(pid, fd, 100)
	if len(abandoned) != 2 {
		t.Fatalf("want 2 abandoned events, got %d", len(abandoned))
	}
	if abandoned[0].Path != "/a" || abandoned[1].Path != "/b" {
		t.Errorf("want /a /b order, got %q %q", abandoned[0].Path, abandoned[1].Path)
	}
}

// Close on an unknown (pid, fd) is a no-op.
func TestPairerCloseUnknownIsNoop(t *testing.T) {
	p := NewPairer()
	if got := p.Close(999, 999, 0); len(got) != 0 {
		t.Errorf("want nil, got %v", got)
	}
}

// Sweep evicts requests older than the timeout and returns abandoned events.
func TestPairerSweepAbandonsTimedOut(t *testing.T) {
	now := time.Now()
	p := newPairerWithClock(func() time.Time { return now })

	pid, fd := uint32(1), int32(1)
	p.Push(Message{TsNs: 1, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/slow"}})

	// advance clock past the timeout
	now = now.Add(31 * time.Second)
	abandoned := p.Sweep(30 * time.Second)
	if len(abandoned) != 1 {
		t.Fatalf("want 1 abandoned, got %d", len(abandoned))
	}
	if abandoned[0].AbandonReason != AbandonReasonTimeout {
		t.Errorf("AbandonReason = %q, want %q", abandoned[0].AbandonReason, AbandonReasonTimeout)
	}
	if abandoned[0].Path != "/slow" {
		t.Errorf("Path = %q, want /slow", abandoned[0].Path)
	}
	if len(p.pending) != 0 {
		t.Error("pending should be empty after sweep")
	}
}

// Sweep keeps requests that have not yet reached the timeout.
func TestPairerSweepKeepsFreshRequests(t *testing.T) {
	now := time.Now()
	p := newPairerWithClock(func() time.Time { return now })

	pid, fd := uint32(1), int32(1)
	p.Push(Message{TsNs: 1, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/fast"}})

	now = now.Add(29 * time.Second)
	if abandoned := p.Sweep(30 * time.Second); len(abandoned) != 0 {
		t.Errorf("want no abandoned events, got %v", abandoned)
	}
	if len(p.pending) != 1 {
		t.Error("fresh request should still be pending")
	}
}

// Sweep on an empty pairer returns nil without panicking.
func TestPairerSweepEmptyNoop(t *testing.T) {
	p := NewPairer()
	if got := p.Sweep(30 * time.Second); len(got) != 0 {
		t.Errorf("want nil, got %v", got)
	}
}

// After Close, a new request on the same (pid, fd) pairs cleanly with
// its response; no phantom state from the evicted request leaks through.
func TestPairerCloseAllowsReuseOfFd(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(7), int32(3)

	// First request queued, then fd closed before any response.
	p.Push(Message{TsNs: 1, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/old"}})
	p.Close(pid, fd, 2)

	// New request on the same (pid, fd) after reuse.
	p.Push(Message{TsNs: 2, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/new"}})
	pe, ok := p.Push(Message{TsNs: 3, Pid: pid, Fd: fd, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	if !ok {
		t.Fatal("response should pair with the new request")
	}
	if pe.Path != "/new" {
		t.Errorf("want path /new, got %q — old request bled through", pe.Path)
	}
}

// Two fds on the same pid must be isolated: closing or pairing on one
// must not affect the other.
func TestPairerConcurrentFdsSamePid(t *testing.T) {
	p := NewPairer()
	pid := uint32(42)
	fd4, fd5 := int32(4), int32(5)

	p.Push(Message{TsNs: 1, Pid: pid, Fd: fd4, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/fd4"}})
	p.Push(Message{TsNs: 2, Pid: pid, Fd: fd5, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/fd5"}})

	// Pair fd5 first; fd4 must still be pending.
	pe5, ok := p.Push(Message{TsNs: 3, Pid: pid, Fd: fd5, IsRequest: false,
		Res: httpStatusLine{status: 201}})
	if !ok || pe5.Path != "/fd5" || pe5.Status != 201 {
		t.Errorf("fd5 pair: got %+v ok=%v", pe5, ok)
	}

	// fd4 queue must be unaffected.
	pe4, ok := p.Push(Message{TsNs: 4, Pid: pid, Fd: fd4, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	if !ok || pe4.Path != "/fd4" || pe4.Status != 200 {
		t.Errorf("fd4 pair: got %+v ok=%v", pe4, ok)
	}
}

// Two processes that happen to use the same fd number must not
// cross-contaminate: (42, fd=4) and (43, fd=4) are distinct streams.
func TestPairerSameFdDifferentPids(t *testing.T) {
	p := NewPairer()
	fd := int32(4)
	pid42, pid43 := uint32(42), uint32(43)

	p.Push(Message{TsNs: 1, Pid: pid42, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/pid42"}})
	p.Push(Message{TsNs: 2, Pid: pid43, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/pid43"}})

	pe43, ok := p.Push(Message{TsNs: 3, Pid: pid43, Fd: fd, IsRequest: false,
		Res: httpStatusLine{status: 201}})
	if !ok || pe43.Path != "/pid43" {
		t.Errorf("pid43 pair: got %+v ok=%v", pe43, ok)
	}

	pe42, ok := p.Push(Message{TsNs: 4, Pid: pid42, Fd: fd, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	if !ok || pe42.Path != "/pid42" {
		t.Errorf("pid42 pair: got %+v ok=%v", pe42, ok)
	}
}

// #171: two concurrent SSL-fallback connections on the same pid (curl-style,
// no verified fd — see #167) must be isolated from each other exactly like
// two fd-keyed connections are (TestPairerConcurrentFdsSamePid). Requests
// and responses are pushed interleaved, not request/request/response/
// response, to prove the FIFO-per-key isolation holds under interleaving,
// not just under a convenient ordering.
func TestPairerSSLFallbackConcurrentSSLsSamePid(t *testing.T) {
	p := NewPairer()
	pid := uint32(42)
	ssl1, ssl2 := uint64(0x1000), uint64(0x2000)

	p.Push(Message{TsNs: 1, Pid: pid, SSL: ssl1, SSLFallback: true, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/ssl1"}})
	p.Push(Message{TsNs: 2, Pid: pid, SSL: ssl2, SSLFallback: true, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/ssl2"}})

	// Respond to ssl2 first; ssl1 must still be pending and pair correctly
	// afterwards — neither response may leak onto the other connection's row.
	pe2, ok := p.Push(Message{TsNs: 3, Pid: pid, SSL: ssl2, SSLFallback: true, IsRequest: false,
		Res: httpStatusLine{status: 201}})
	if !ok || pe2.Path != "/ssl2" || pe2.Status != 201 {
		t.Errorf("ssl2 pair: got %+v ok=%v", pe2, ok)
	}
	pe1, ok := p.Push(Message{TsNs: 4, Pid: pid, SSL: ssl1, SSLFallback: true, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	if !ok || pe1.Path != "/ssl1" || pe1.Status != 200 {
		t.Errorf("ssl1 pair: got %+v ok=%v", pe1, ok)
	}
}

// #171's central safety guarantee: an SSLFallback message and an ordinary
// fd-keyed message on the same pid must never collide even when Fd and SSL
// happen to carry the identical numeric value. If the pairer only had one
// bare (pid, number) key without the sslFallback discriminator, fd=7 and
// ssl=7 on the same pid would be indistinguishable and this test would fail
// by cross-pairing curl's plaintext response onto the unrelated fd=7
// connection's request (or vice versa).
func TestPairerSSLFallbackNeverCollidesWithSameNumericFd(t *testing.T) {
	p := NewPairer()
	pid := uint32(42)
	const sameValue = 7 // used as both a real fd and an SSL* value below

	// Queue order: fd-keyed request first, then ssl-keyed request. If both
	// collapsed onto one shared (pid, 7) FIFO, it would now hold
	// [/fd-keyed, /ssl-keyed] in that order.
	p.Push(Message{TsNs: 1, Pid: pid, Fd: sameValue, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/fd-keyed"}})
	p.Push(Message{TsNs: 2, Pid: pid, SSL: sameValue, SSLFallback: true, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/ssl-keyed"}})

	// Respond to the ssl-keyed request FIRST — the reverse of queue order.
	// Under a collided shared FIFO this would incorrectly pop the
	// fd-keyed request (queued first) and return "/fd-keyed" here; the
	// discriminator must instead route it to its own single-entry queue.
	peSSL, ok := p.Push(Message{TsNs: 3, Pid: pid, SSL: sameValue, SSLFallback: true, IsRequest: false,
		Res: httpStatusLine{status: 201}})
	if !ok || peSSL.Path != "/ssl-keyed" {
		t.Fatalf("ssl-keyed pair: got %+v ok=%v, want /ssl-keyed", peSSL, ok)
	}

	// The fd-keyed request must still be queued, untouched, and pair with
	// its own response next.
	peFd, ok := p.Push(Message{TsNs: 4, Pid: pid, Fd: sameValue, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	if !ok || peFd.Path != "/fd-keyed" {
		t.Fatalf("fd-keyed pair: got %+v ok=%v, want /fd-keyed", peFd, ok)
	}
}

// A malformed SSLFallback message with SSL==0 must be dropped, not queued
// or paired — keying it on (pid, ssl=0) would collapse every such message
// for a pid onto one shared FIFO, defeating the discriminator's whole
// purpose. Two independently-malformed requests on the same pid must not
// cross-pair with each other's responses either (Copilot review, PR #172).
func TestPairerSSLFallbackZeroSSLIsDropped(t *testing.T) {
	p := NewPairer()
	pid := uint32(42)

	if _, ok := p.Push(Message{TsNs: 1, Pid: pid, SSL: 0, SSLFallback: true, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/a"}}); ok {
		t.Error("a request must never itself report as paired")
	}
	if _, ok := p.Push(Message{TsNs: 2, Pid: pid, SSL: 0, SSLFallback: true, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/b"}}); ok {
		t.Error("a request must never itself report as paired")
	}
	if len(p.pending) != 0 {
		t.Errorf("malformed SSLFallback requests must not be queued, pending = %+v", p.pending)
	}

	// A response for the malformed identity must not pair with either
	// dropped request (there is nothing valid to pair with).
	if pe, ok := p.Push(Message{TsNs: 3, Pid: pid, SSL: 0, SSLFallback: true, IsRequest: false,
		Res: httpStatusLine{status: 200}}); ok {
		t.Errorf("malformed SSLFallback response must not pair, got %+v", pe)
	}
}

// A successful pairing carries SSL/SSLFallback from the request into the
// PairedEvent, so renderers downstream can tell it apart from a verified
// pairing (#171).
func TestPairerSSLFallbackCarriesIntoPairedEvent(t *testing.T) {
	p := NewPairer()
	pid, ssl := uint32(1), uint64(0xabc)

	p.Push(Message{TsNs: 1, Pid: pid, SSL: ssl, SSLFallback: true, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/x"}})
	pe, ok := p.Push(Message{TsNs: 2, Pid: pid, SSL: ssl, SSLFallback: true, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	if !ok {
		t.Fatal("want paired event")
	}
	if !pe.SSLFallback || pe.SSL != ssl {
		t.Errorf("PairedEvent SSL=%#x SSLFallback=%v, want %#x true", pe.SSL, pe.SSLFallback, ssl)
	}
}

// Close is fd-driven — a real close syscall always carries a real fd — so it
// must never evict a pending SSLFallback request even when the fd passed to
// Close numerically matches the pending request's SSL* value (#171: no
// guessed/inferred fd correlation for SSLFallback messages).
func TestPairerCloseNeverEvictsSSLFallback(t *testing.T) {
	p := NewPairer()
	pid := uint32(42)
	const sameValue = 9

	p.Push(Message{TsNs: 1, Pid: pid, SSL: sameValue, SSLFallback: true, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/ssl-keyed"}})

	if got := p.Close(pid, sameValue, 2); len(got) != 0 {
		t.Errorf("Close(fd=%d) must not evict an SSLFallback request keyed on SSL=%d, got %+v", sameValue, sameValue, got)
	}

	// The request must still be there, pairing normally.
	pe, ok := p.Push(Message{TsNs: 3, Pid: pid, SSL: sameValue, SSLFallback: true, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	if !ok || pe.Path != "/ssl-keyed" {
		t.Errorf("want the SSLFallback request to survive Close and pair normally, got %+v ok=%v", pe, ok)
	}
}

// CloseSSL is the SSLFallback counterpart to Close (#173) — confirm it
// evicts a pending SSLFallback request keyed on the same (pid, ssl), and
// that the resulting abandoned event is reported with AbandonReasonClosed
// exactly like a real fd close does.
func TestPairerCloseSSLEvictsSSLFallback(t *testing.T) {
	p := NewPairer()
	pid, ssl := uint32(42), uint64(9)

	p.Push(Message{TsNs: 1, Pid: pid, SSL: ssl, SSLFallback: true, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/ssl-free"}})

	got := p.CloseSSL(pid, ssl, 5)
	if len(got) != 1 {
		t.Fatalf("CloseSSL: want 1 abandoned event, got %d", len(got))
	}
	if !got[0].Abandoned || got[0].AbandonReason != AbandonReasonClosed {
		t.Errorf("CloseSSL: Abandoned=%v AbandonReason=%q, want true/%q", got[0].Abandoned, got[0].AbandonReason, AbandonReasonClosed)
	}
	if !got[0].SSLFallback || got[0].SSL != ssl {
		t.Errorf("CloseSSL: SSL=%#x SSLFallback=%v, want %#x/true", got[0].SSL, got[0].SSLFallback, ssl)
	}
	if got[0].Path != "/ssl-free" {
		t.Errorf("CloseSSL: Path = %q, want /ssl-free", got[0].Path)
	}

	// The request must be gone — a second CloseSSL call finds nothing.
	if got := p.CloseSSL(pid, ssl, 6); len(got) != 0 {
		t.Errorf("CloseSSL: request should already be evicted, got %+v", got)
	}
}

// CloseSSL must never evict an ordinary fd-keyed pending request, even when
// its numeric fd happens to equal the ssl value CloseSSL was called with —
// the mirror image of TestPairerCloseNeverEvictsSSLFallback, confirming
// keyFor's discriminator protects both directions.
func TestPairerCloseSSLNeverEvictsFdKeyed(t *testing.T) {
	p := NewPairer()
	pid := uint32(42)
	const sameValue = 9

	p.Push(Message{TsNs: 1, Pid: pid, Fd: sameValue, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/fd-keyed"}})

	if got := p.CloseSSL(pid, sameValue, 2); len(got) != 0 {
		t.Errorf("CloseSSL(ssl=%d) must not evict an fd-keyed request with Fd=%d, got %+v", sameValue, sameValue, got)
	}

	pe, ok := p.Push(Message{TsNs: 3, Pid: pid, Fd: sameValue, IsRequest: false,
		Res: httpStatusLine{status: 200}})
	if !ok || pe.Path != "/fd-keyed" {
		t.Errorf("want the fd-keyed request to survive CloseSSL and pair normally, got %+v ok=%v", pe, ok)
	}
}

// Sweep remains the fallback eviction path for both key spaces when neither
// Close nor CloseSSL ever fires (e.g. a hard crash) — confirm it still works
// for SSLFallback requests, and that the resulting abandoned event still
// carries SSL/SSLFallback.
func TestPairerSweepEvictsSSLFallbackTimeout(t *testing.T) {
	now := time.Now()
	p := newPairerWithClock(func() time.Time { return now })

	pid, ssl := uint32(1), uint64(0x42)
	p.Push(Message{TsNs: 1, Pid: pid, SSL: ssl, SSLFallback: true, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/slow"}})

	now = now.Add(31 * time.Second)
	abandoned := p.Sweep(30 * time.Second)
	if len(abandoned) != 1 {
		t.Fatalf("want 1 abandoned, got %d", len(abandoned))
	}
	if !abandoned[0].SSLFallback || abandoned[0].SSL != ssl {
		t.Errorf("abandoned SSL=%#x SSLFallback=%v, want %#x true", abandoned[0].SSL, abandoned[0].SSLFallback, ssl)
	}
	if abandoned[0].AbandonReason != AbandonReasonTimeout {
		t.Errorf("AbandonReason = %q, want %q", abandoned[0].AbandonReason, AbandonReasonTimeout)
	}
}

// 1000 short keep-alive cycles: request + response + Close. No pending
// entries must survive after the burst.
func TestPairerLeakSmokeTest(t *testing.T) {
	p := NewPairer()
	pid := uint32(1)

	for i := range 1000 {
		fd := int32(i % 10)
		p.Push(Message{TsNs: uint64(i*2), Pid: pid, Fd: fd, IsRequest: true,
			Req: httpRequestLine{method: "GET", path: "/x"}})
		p.Push(Message{TsNs: uint64(i*2 + 1), Pid: pid, Fd: fd, IsRequest: false,
			Res: httpStatusLine{status: 200}})
		p.Close(pid, fd, 0)
	}

	if len(p.pending) != 0 {
		t.Errorf("leak after 1000 cycles: %d pending entries remain", len(p.pending))
	}
}
