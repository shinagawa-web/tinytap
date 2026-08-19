package drops

import (
	"fmt"
	"strings"
)

type Counts struct {
	Ringbuf uint64
	MapFull uint64
	// TLSAttachSkips counts TLS processes skipped because the concurrent-attach
	// semaphore was full. Each skip means that process's TLS traffic was not
	// captured. Incremented by sslWatcher when it throttles a BPF load (#326).
	TLSAttachSkips uint64
}

func (c Counts) Total() uint64 { return c.Ringbuf + c.MapFull }

func (c Counts) Add(o Counts) Counts {
	return Counts{
		Ringbuf:        c.Ringbuf + o.Ringbuf,
		MapFull:        c.MapFull + o.MapFull,
		TLSAttachSkips: c.TLSAttachSkips + o.TLSAttachSkips,
	}
}

func (c Counts) Summary() string {
	var parts []string
	if c.Total() > 0 {
		parts = append(parts, fmt.Sprintf("drops: %d events lost — capture is incomplete (ring buffer full: %d, state map full: %d)",
			c.Total(), c.Ringbuf, c.MapFull))
	}
	if c.TLSAttachSkips > 0 {
		parts = append(parts, fmt.Sprintf("TLS attach skipped: %d process(es) — BPF load throttled under high churn; consider raising max-concurrent-attach",
			c.TLSAttachSkips))
	}
	return strings.Join(parts, "\n")
}
