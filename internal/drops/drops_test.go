package drops_test

import (
	"strings"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/drops"
)

func TestCounts_Total(t *testing.T) {
	c := drops.Counts{Ringbuf: 3, MapFull: 4}
	if got := c.Total(); got != 7 {
		t.Errorf("Total() = %d, want 7", got)
	}
}

func TestCounts_Add(t *testing.T) {
	a := drops.Counts{Ringbuf: 1, MapFull: 2, TLSAttachSkips: 3}
	b := drops.Counts{Ringbuf: 10, MapFull: 20, TLSAttachSkips: 30}
	got := a.Add(b)
	want := drops.Counts{Ringbuf: 11, MapFull: 22, TLSAttachSkips: 33}
	if got != want {
		t.Errorf("Add() = %+v, want %+v", got, want)
	}
}

func TestCounts_Summary_Zero(t *testing.T) {
	if got := (drops.Counts{}).Summary(); got != "" {
		t.Errorf("Summary() = %q, want empty", got)
	}
}

func TestCounts_Summary_NonZero(t *testing.T) {
	c := drops.Counts{Ringbuf: 5, MapFull: 2}
	got := c.Summary()
	for _, want := range []string{"7", "ring buffer full: 5", "state map full: 2"} {
		if !strings.Contains(got, want) {
			t.Errorf("Summary() = %q, want it to contain %q", got, want)
		}
	}
}

func TestCounts_Summary_TLSAttachSkipsOnly(t *testing.T) {
	c := drops.Counts{TLSAttachSkips: 9}
	got := c.Summary()
	if !strings.Contains(got, "TLS attach skipped: 9") {
		t.Errorf("Summary() = %q, want it to contain TLS attach skip count", got)
	}
	if strings.Contains(got, "events lost") {
		t.Errorf("Summary() = %q, must not mention events lost when BPF drops are zero", got)
	}
}

func TestCounts_Summary_Both(t *testing.T) {
	c := drops.Counts{Ringbuf: 1, TLSAttachSkips: 3}
	got := c.Summary()
	if !strings.Contains(got, "events lost") {
		t.Errorf("Summary() = %q, want BPF drop line", got)
	}
	if !strings.Contains(got, "TLS attach skipped: 3") {
		t.Errorf("Summary() = %q, want TLS attach skip line", got)
	}
}
