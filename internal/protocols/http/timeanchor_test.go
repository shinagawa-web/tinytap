package http

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

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

func TestNewTimeAnchorCorrelatesRealClocks(t *testing.T) {
	before := time.Now()
	a := NewTimeAnchor()
	after := time.Now()

	if a.wallStart.Before(before) || a.wallStart.After(after) {
		t.Errorf("wallStart=%v should fall within [%v, %v]", a.wallStart, before, after)
	}
	if got := a.WallTime(a.bpfStart); !got.Equal(a.wallStart) {
		t.Errorf("WallTime(bpfStart) = %v, want %v", got, a.wallStart)
	}
}

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
