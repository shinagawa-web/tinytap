package http

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

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
