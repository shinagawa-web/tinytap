package http

import (
	"fmt"
	"time"
)

// TimeAnchor converts BPF ktime (monotonic ns since boot) values into
// wall clock time by remembering the first (wall, ktime) pair we observed
// and linearly extrapolating from there. This is accurate to within the
// userspace processing delay of the first event (sub-millisecond in
// practice) — good enough for the demo line but not for ground-truth
// forensics. A future refactor could switch to clock_gettime(CLOCK_BOOTTIME)
// for a static offset that doesn't depend on the first event.
type TimeAnchor struct {
	wallStart time.Time
	bpfStart  uint64
	set       bool
}

func (a *TimeAnchor) WallTime(tsNs uint64) time.Time {
	if !a.set {
		a.wallStart = time.Now()
		a.bpfStart = tsNs
		a.set = true
	}
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
//	12:47:57.005  python3[27122]  GET   /                        200    1304B     0.3ms
func RenderPaired(p PairedEvent, when time.Time) string {
	latencyMs := float64(p.Latency) / float64(time.Millisecond)
	who := fmt.Sprintf("%s[%d]", p.Comm, p.Pid)
	line := fmt.Sprintf("%s  %-16s %-5s %-24s %3d %8s %9s",
		when.Format("15:04:05.000"),
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
//	12:47:57.005  curl[1234]       GET   /api                     ABANDONED     12.3ms  (peer closed)
func RenderAbandoned(p PairedEvent, when time.Time) string {
	latencyMs := float64(p.Latency) / float64(time.Millisecond)
	who := fmt.Sprintf("%s[%d]", p.Comm, p.Pid)
	line := fmt.Sprintf("%s  %-16s %-5s %-24s %-12s %9s  (%s)",
		when.Format("15:04:05.000"),
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
