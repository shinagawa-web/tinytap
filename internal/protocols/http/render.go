package http

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// timeFormat is the layout used by RenderPaired/RenderAbandoned. It carries
// full date and a fixed-width timezone offset (never the bare "Z" RFC 3339
// allows for UTC) so every stdout line is unambiguous once redirected to a
// file and read back later, independent of the reader's local time (#193).
const timeFormat = "2006-01-02T15:04:05.000-07:00"

// TimeAnchor converts BPF ktime (monotonic ns since boot) values into wall
// clock time via a single fixed (wall, ktime) correlation point captured once
// by NewTimeAnchor. Every timestamp is then a pure linear offset from that
// point, so accuracy no longer depends on how long any particular event took
// to reach userspace — the previous design anchored on the first observed
// event instead, inheriting that event's (usually sub-millisecond, but
// unbounded in the worst case) delivery delay as error for every timestamp
// after it.
type TimeAnchor struct {
	wallStart time.Time
	bpfStart  uint64
}

// NewTimeAnchor samples wall-clock time and CLOCK_MONOTONIC back-to-back.
// CLOCK_MONOTONIC is the same clock domain the kernel's bpf_ktime_get_ns()
// reads (bpf-helpers(7): "time elapsed since system boot... does not include
// time the system was suspended") — so the two readings correlate directly
// with the ktime values events arrive with. clock_gettime cannot fail for
// this fixed, valid clock id on Linux, so its error return is discarded.
func NewTimeAnchor() TimeAnchor {
	var ts unix.Timespec
	wall := time.Now()
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return TimeAnchor{wallStart: wall, bpfStart: uint64(ts.Nano())}
}

func (a TimeAnchor) WallTime(tsNs uint64) time.Time {
	delta := int64(tsNs) - int64(a.bpfStart)
	return a.wallStart.Add(time.Duration(delta))
}

// sslFallbackMarker is appended to a rendered line when PairedEvent.SSLFallback
// is true, so a (pid, SSL*)-keyed exchange (#171 — e.g. curl, which never
// calls SSL_set_fd, #167) never reads as an ordinary fd-verified pairing.
// Appended as trailing text rather than a new column: existing rows'
// layout — and any grep/awk over it (#63) — is untouched, since today no
// message ever sets SSLFallback and this marker never appears.
const sslFallbackMarker = "  [ssl-keyed, fd unverified]"

// RenderPaired returns the one-line summary of a paired exchange: a single
// self-contained line that reads top-to-bottom for a human and splits on
// whitespace for grep/awk (#63). The HTTP versions and the reason phrase are
// dropped from this line — the status code carries the gist, and the full
// start lines show up under `-v` via RenderPairedDetail. The column widths
// keep typical short paths aligned; long paths overflow rather than truncate.
//
//	2026-08-01T12:47:57.005+09:00  python3[27122]  GET   /                        200    1304B     0.3ms
func RenderPaired(p PairedEvent, when time.Time) string {
	latencyMs := float64(p.Latency) / float64(time.Millisecond)
	who := fmt.Sprintf("%s[%d]", p.Comm, p.Pid)
	line := fmt.Sprintf("%s  %-16s %-5s %-24s %3d %8s %9s",
		when.Format(timeFormat),
		who,
		p.Method, p.Path, p.Status,
		fmt.Sprintf("%dB", p.ResBytes),
		fmt.Sprintf("%.1fms", latencyMs))
	if p.SSLFallback {
		line += sslFallbackMarker
	}
	return line
}

// RenderAbandoned returns the one-line summary for a request that never
// received a response. Columns align with RenderPaired: the status+bytes
// field (12 chars) is replaced by the literal "ABANDONED".
//
//	2026-08-01T12:47:57.005+09:00  curl[1234]       GET   /api                     ABANDONED     12.3ms  (peer closed)
func RenderAbandoned(p PairedEvent, when time.Time) string {
	latencyMs := float64(p.Latency) / float64(time.Millisecond)
	who := fmt.Sprintf("%s[%d]", p.Comm, p.Pid)
	line := fmt.Sprintf("%s  %-16s %-5s %-24s %-12s %9s  (%s)",
		when.Format(timeFormat),
		who,
		p.Method, p.Path,
		"ABANDONED",
		fmt.Sprintf("%.1fms", latencyMs),
		p.AbandonReason)
	if p.SSLFallback {
		line += sslFallbackMarker
	}
	return line
}

// RenderPairedDetail returns the `-v` continuation lines for an exchange: the
// request start line and headers (prefixed `>`), then the response start line
// and headers (prefixed `<`), in on-wire order. Indented so they read as
// belonging to the summary line above. Body contents follow once #35 lands.
func RenderPairedDetail(p PairedEvent) []string {
	lines := make([]string, 0, len(p.ReqHeaders)+len(p.ResHeaders)+2)
	lines = append(lines, fmt.Sprintf("    > %s %s %s", p.Method, p.Path, p.ReqVersion))
	for _, h := range p.ReqHeaders {
		lines = append(lines, fmt.Sprintf("    > %s: %s", h.Name, h.Value))
	}
	lines = append(lines, fmt.Sprintf("    < %s %d %s", p.ResVersion, p.Status, p.Reason))
	for _, h := range p.ResHeaders {
		lines = append(lines, fmt.Sprintf("    < %s: %s", h.Name, h.Value))
	}
	return lines
}
