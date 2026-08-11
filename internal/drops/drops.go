package drops

import "fmt"

type Counts struct {
	Ringbuf uint64
	MapFull uint64
}

func (c Counts) Total() uint64 { return c.Ringbuf + c.MapFull }

func (c Counts) Add(o Counts) Counts {
	return Counts{Ringbuf: c.Ringbuf + o.Ringbuf, MapFull: c.MapFull + o.MapFull}
}

func (c Counts) Summary() string {
	if c.Total() == 0 {
		return ""
	}
	return fmt.Sprintf("drops: %d events lost — capture is incomplete (ring buffer full: %d, state map full: %d)",
		c.Total(), c.Ringbuf, c.MapFull)
}
