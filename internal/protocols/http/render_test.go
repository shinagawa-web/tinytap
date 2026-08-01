package http

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
	want := "2026-06-08T19:35:24.123+00:00  python3[5936]    GET   /                        200     649B     1.2ms"
	if got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

// A truncated response body prints "<kept>/<total>B" instead of the plain
// "<total>B" (#190), so stdout can distinguish a full capture from a
// partial one without relying on the TUI.
func TestRenderPairedResponseBodyTruncated(t *testing.T) {
	pe := PairedEvent{
		Pid: 5936, Fd: 7, Comm: "python3",
		Method: "GET", Path: "/", ReqVersion: "HTTP/1.1",
		Status: 200, Reason: "OK", ResVersion: "HTTP/1.0",
		ResBytes: 1304, ResBody: make([]byte, 512), ResBodyTruncated: true,
		Latency: 300 * time.Microsecond,
	}
	when := time.Date(2026, 6, 8, 19, 35, 24, 123_000_000, time.UTC)
	got := RenderPaired(pe, when)
	if !strings.Contains(got, "512/1304B") {
		t.Errorf("truncated line should show kept/total bytes, got %q", got)
	}
	if strings.Contains(got, " 1304B") {
		t.Errorf("truncated line should not also show the plain total, got %q", got)
	}
}

// An untruncated response's line is unaffected — same "<total>B" format as
// before ResBodyTruncated existed (#190's "Done when": byte-for-byte
// unchanged for the untruncated case).
func TestRenderPairedResponseBodyNotTruncatedUnchanged(t *testing.T) {
	pe := PairedEvent{
		Pid: 5936, Fd: 7, Comm: "python3",
		Method: "GET", Path: "/", ReqVersion: "HTTP/1.1",
		Status: 200, Reason: "OK", ResVersion: "HTTP/1.0",
		ResBytes: 649,
		Latency:  1200 * time.Microsecond,
	}
	when := time.Date(2026, 6, 8, 19, 35, 24, 123_000_000, time.UTC)
	got := RenderPaired(pe, when)
	want := "2026-06-08T19:35:24.123+00:00  python3[5936]    GET   /                        200     649B     1.2ms"
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
	want := "2026-06-08T12:47:57.005+00:00  curl[1234]       GET   /api                     ABANDONED       12.3ms  (peer closed)"
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

// WallTime is a pure linear offset from the anchor's fixed (wall, ktime)
// point — unlike the previous design, no call re-anchors it. This covers
// both directions: a ktime after the anchor and one before it (a request
// that landed slightly earlier than the response the anchor happened to be
// taken from).
func TestTimeAnchorWallTimeIsLinearInKtime(t *testing.T) {
	a := TimeAnchor{wallStart: time.Date(2026, 6, 8, 19, 35, 24, 0, time.UTC), bpfStart: 2_000_000_000}
	resWall := a.WallTime(2_000_000_000)
	reqWall := a.WallTime(2_000_000_000 - 5_000_000)
	laterWall := a.WallTime(2_000_000_000 + 5_000_000)
	if !resWall.Equal(a.wallStart) {
		t.Errorf("WallTime at the anchor ktime should equal wallStart, got %v", resWall)
	}
	if delta := resWall.Sub(reqWall); delta != 5*time.Millisecond {
		t.Errorf("want 5ms gap before the anchor, got %v", delta)
	}
	if delta := laterWall.Sub(resWall); delta != 5*time.Millisecond {
		t.Errorf("want 5ms gap after the anchor, got %v", delta)
	}
}

// NewTimeAnchor must correlate real wall-clock and monotonic time at the
// moment it's called, not at whatever moment the first event happens to
// arrive (#193).
func TestNewTimeAnchorCorrelatesRealClocks(t *testing.T) {
	before := time.Now()
	a := NewTimeAnchor()
	after := time.Now()

	if a.wallStart.Before(before) || a.wallStart.After(after) {
		t.Errorf("wallStart=%v should fall within [%v, %v]", a.wallStart, before, after)
	}
	// WallTime at the anchor's own ktime must reproduce wallStart exactly.
	if got := a.WallTime(a.bpfStart); !got.Equal(a.wallStart) {
		t.Errorf("WallTime(bpfStart) = %v, want %v", got, a.wallStart)
	}
}

// A clock_gettime failure must not be silently swallowed into a zero-valued
// anchor that would corrupt every later WallTime conversion with no signal
// — NewTimeAnchor must fail loud instead.
func TestNewTimeAnchorPanicsOnClockGettimeError(t *testing.T) {
	orig := clockGettime
	defer func() { clockGettime = orig }()
	clockGettime = func(int32, *unix.Timespec) error {
		return errors.New("simulated clock_gettime failure")
	}

	defer func() {
		if recover() == nil {
			t.Error("NewTimeAnchor should panic when clock_gettime fails")
		}
	}()
	NewTimeAnchor()
}
