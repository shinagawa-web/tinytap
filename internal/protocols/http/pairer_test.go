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
