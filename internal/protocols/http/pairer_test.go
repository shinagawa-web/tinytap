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

// Close drops the pending request for the given (pid, fd); a response
// arriving after Close must not pair.
func TestPairerCloseDropsPending(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(7), int32(3)

	req := Message{TsNs: 1, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/x", version: "HTTP/1.1"}}
	p.Push(req)

	p.Close(pid, fd)

	res := Message{TsNs: 2, Pid: pid, Fd: fd, IsRequest: false,
		Res: httpStatusLine{version: "HTTP/1.1", status: 200, reason: "OK"}}
	if _, ok := p.Push(res); ok {
		t.Error("response after Close should not pair with the evicted request")
	}
}

// Close on an unknown (pid, fd) is a no-op.
func TestPairerCloseUnknownIsNoop(t *testing.T) {
	p := NewPairer()
	p.Close(999, 999)
}

// After Close, a new request on the same (pid, fd) pairs cleanly with
// its response; no phantom state from the evicted request leaks through.
func TestPairerCloseAllowsReuseOfFd(t *testing.T) {
	p := NewPairer()
	pid, fd := uint32(7), int32(3)

	// First request queued, then fd closed before any response.
	p.Push(Message{TsNs: 1, Pid: pid, Fd: fd, IsRequest: true,
		Req: httpRequestLine{method: "GET", path: "/old"}})
	p.Close(pid, fd)

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
		p.Close(pid, fd)
	}

	if len(p.pending) != 0 {
		t.Errorf("leak after 1000 cycles: %d pending entries remain", len(p.pending))
	}
}
