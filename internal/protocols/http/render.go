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

// RenderPaired returns the v0.1.0 demo line, expanded to carry the
// request/response HTTP versions and the reason phrase. Compared to the
// minimal form in Issue #4 (`GET / → 200 649 bytes (1.2ms)`), this layout
// surfaces HTTP/1.0 vs HTTP/1.1 (relevant for keep-alive framing) and the
// reason phrase (useful when status codes alone are ambiguous, e.g. 4xx).
//
//	[19:35:24.123] pid=5936 (python3) GET / HTTP/1.1 → HTTP/1.0 200 OK 649 bytes (1.2ms)
func RenderPaired(p PairedEvent, when time.Time) string {
	latencyMs := float64(p.Latency) / float64(time.Millisecond)
	return fmt.Sprintf("[%s] pid=%d (%s) %s %s %s → %s %d %s %d bytes (%.1fms)",
		when.Format("15:04:05.000"),
		p.Pid, p.Comm,
		p.Method, p.Path, p.ReqVersion,
		p.ResVersion, p.Status, p.Reason,
		p.ResBytes, latencyMs)
}
