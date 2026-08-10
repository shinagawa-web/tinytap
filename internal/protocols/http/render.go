package http

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const timeFormat = "2006-01-02T15:04:05.000-07:00"

type TimeAnchor struct {
	wallStart time.Time
	bpfStart  uint64
}

var clockGettime = unix.ClockGettime

func NewTimeAnchor() TimeAnchor {
	var ts unix.Timespec
	wall := time.Now()
	if err := clockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		panic(fmt.Sprintf("clock_gettime(CLOCK_MONOTONIC): %v", err))
	}
	return TimeAnchor{wallStart: wall, bpfStart: uint64(ts.Nano())}
}

func (a TimeAnchor) WallTime(tsNs uint64) time.Time {
	delta := int64(tsNs) - int64(a.bpfStart)
	return a.wallStart.Add(time.Duration(delta))
}

const sslFallbackMarker = "  [ssl-keyed, fd unverified]"

// 2026-08-01T12:47:57.005+09:00  python3[27122]  GET   /                        200    1304B     0.3ms
// 2026-08-01T12:47:57.005+09:00  python3[27122]  GET   /                        200  512/1304B     0.3ms
func RenderPaired(p PairedEvent, when time.Time) string {
	p = roundTripJSONL(p)
	latencyMs := float64(p.Latency) / float64(time.Millisecond)
	who := fmt.Sprintf("%s[%d]", p.Comm, p.Pid)
	resBytes := fmt.Sprintf("%dB", p.ResBytes)
	if p.ResBodyTruncated {
		resBytes = fmt.Sprintf("%d/%dB", len(p.ResBody), p.ResBytes)
	}
	line := fmt.Sprintf("%s  %-16s %-5s %-24s %3d %8s %9s",
		when.Format(timeFormat),
		who,
		p.Method, p.Path, p.Status,
		resBytes,
		fmt.Sprintf("%.1fms", latencyMs))
	if p.SSLFallback {
		line += sslFallbackMarker
	}
	return line
}

// 2026-08-01T12:47:57.005+09:00  curl[1234]       GET   /api                     ABANDONED     12.3ms  (peer closed)
func RenderAbandoned(p PairedEvent, when time.Time) string {
	p = roundTripJSONL(p)
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

func RenderPairedDetail(p PairedEvent) []string {
	p = roundTripJSONL(p)
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
