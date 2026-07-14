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

func TestRenderAbandonedFormat(t *testing.T) {
	pe := PairedEvent{
		Pid: 1234, Comm: "curl",
		Method: "GET", Path: "/api",
		Latency:       12_300 * time.Microsecond,
		Abandoned:     true,
		AbandonReason: AbandonReasonClosed,
	}
	when := time.Date(2026, 6, 8, 12, 47, 57, 5_000_000, time.UTC)
	got := RenderAbandoned(pe, when)
	want := "12:47:57.005  curl[1234]       GET   /api                     ABANDONED       12.3ms  (peer closed)"
	if got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

// An SSLFallback pairing (#171 — matched on (pid, SSL*), not a verified fd)
// gets a trailing marker so it never reads as an ordinary fd-verified pair;
// an fd-verified pairing's line is untouched (byte-for-byte the same as
// before SSLFallback existed).
func TestRenderPairedSSLFallbackMarker(t *testing.T) {
	base := PairedEvent{
		Pid: 5936, Fd: 7, Comm: "curl",
		Method: "GET", Path: "/", ReqVersion: "HTTP/1.1",
		Status: 200, Reason: "OK", ResVersion: "HTTP/1.0",
		ResBytes: 649, Latency: 1200 * time.Microsecond,
	}
	when := time.Date(2026, 6, 8, 19, 35, 24, 123_000_000, time.UTC)

	verified := RenderPaired(base, when)
	if strings.Contains(verified, "ssl-keyed") {
		t.Errorf("fd-verified line should carry no marker, got %q", verified)
	}

	fallback := base
	fallback.SSLFallback = true
	got := RenderPaired(fallback, when)
	if !strings.Contains(got, "ssl-keyed") {
		t.Errorf("SSLFallback line should carry the marker, got %q", got)
	}
	if got != verified+sslFallbackMarker {
		t.Errorf("SSLFallback line should be the verified line plus the marker\n got: %q\nwant: %q", got, verified+sslFallbackMarker)
	}
}

// Same marker behavior for RenderAbandoned.
func TestRenderAbandonedSSLFallbackMarker(t *testing.T) {
	base := PairedEvent{
		Pid: 1234, Comm: "curl",
		Method: "GET", Path: "/api",
		Latency: 12_300 * time.Microsecond, Abandoned: true,
		AbandonReason: AbandonReasonClosed,
	}
	when := time.Date(2026, 6, 8, 12, 47, 57, 5_000_000, time.UTC)

	verified := RenderAbandoned(base, when)
	fallback := base
	fallback.SSLFallback = true
	got := RenderAbandoned(fallback, when)
	if got != verified+sslFallbackMarker {
		t.Errorf("SSLFallback abandoned line should be the verified line plus the marker\n got: %q\nwant: %q", got, verified+sslFallbackMarker)
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
