package http

import (
	"strings"
	"testing"
	"time"
)

func TestRenderPairedEventMatchesSpecFormat(t *testing.T) {
	pe := PairedEvent{
		Pid: 5936, Fd: 7, Comm: "python3",
		Method: "GET", Path: "/", ReqVersion: "HTTP/1.1",
		Status: 200, Reason: "OK", ResVersion: "HTTP/1.0",
		ResBytes: 649,
		Latency:  1200 * time.Microsecond,
	}
	when := time.Date(2026, 6, 8, 19, 35, 24, 123_000_000, time.UTC)
	got := RenderPaired(pe, when)
	want := "19:35:24.123  python3[5936]    GET   /                        200     649B     1.2ms"
	if got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestRenderPairedDetailHasStartLinesAndHeaders(t *testing.T) {
	pe := PairedEvent{
		Method: "GET", Path: "/", ReqVersion: "HTTP/1.1",
		Status: 200, Reason: "OK", ResVersion: "HTTP/1.0",
		ReqHeaders: []Header{{Name: "Host", Value: "localhost:8081"}},
		ResHeaders: []Header{{Name: "Content-Type", Value: "text/html"}},
	}
	want := []string{
		"    > GET / HTTP/1.1",
		"    > Host: localhost:8081",
		"    < HTTP/1.0 200 OK",
		"    < Content-Type: text/html",
	}
	got := RenderPairedDetail(pe)
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d:\n got: %q\nwant: %q", i, got[i], want[i])
		}
	}
}

// TimeAnchor must extrapolate correctly for events whose ktime is before
// (smaller than) the anchor — a request that landed slightly earlier than
// its response, where we anchor on the response.
func TestTimeAnchorExtrapolatesBackwards(t *testing.T) {
	var a TimeAnchor
	resTs := uint64(2_000_000_000)
	resWall := a.WallTime(resTs)
	// Request 5 ms earlier (in BPF ns).
	reqWall := a.WallTime(resTs - 5_000_000)
	if delta := resWall.Sub(reqWall); delta != 5*time.Millisecond {
		t.Errorf("want 5ms gap, got %v", delta)
	}
	// Anchoring is one-shot; the second event must not have reset it.
	if !strings.HasPrefix(reqWall.Format("15:04:05.000"), resWall.Add(-5*time.Millisecond).Format("15:04:05.00")) {
		t.Errorf("reqWall=%v should be 5ms before resWall=%v", reqWall, resWall)
	}
}
