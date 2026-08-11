//go:build privileged

package main

import (
	"os"
	"testing"
)

// TestLoadBPF_DropCountsReflectsRealOverflow drives an undrained pipe past
// the events ring's capacity through the real production wiring —
// loadBPF (bpf.go's init() closure, not a stub) -> tinytapSession.drops ->
// Tinytap.DropCounts() — and confirms the session's dropCounts() reflects
// a real kernel-level drop, not just that the field is non-nil.
func TestLoadBPF_DropCountsReflectsRealOverflow(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root / CAP_BPF")
	}

	sess, err := loadBPF(0)
	if err != nil {
		t.Fatalf("loadBPF: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	const maxWrites = 6000
	buf := []byte("x")
	for i := 0; i < maxWrites; i++ {
		if _, err := w.Write(buf); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if sess.dropCounts().Ringbuf > 0 {
			return
		}
	}
	t.Fatalf("Ringbuf drop count still 0 after %d writes with nothing draining the ring", maxWrites)
}
