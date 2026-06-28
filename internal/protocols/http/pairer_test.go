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

func TestPairerDropsOrphanResponse(t *testing.T) {
	p := NewPairer()
	res := Message{TsNs: 100, Pid: 42, Fd: 7, IsRequest: false,
		Res: httpStatusLine{status: 200}}
	if pe, ok := p.Push(res); ok {
		t.Errorf("orphan response should not pair, got %+v", pe)
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
