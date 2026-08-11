//go:build privileged

package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/loader"
)

// TestReportDrops_RealRingbufDrop forces a genuine ring buffer overflow on
// the real BPF object (same technique as internal/loader's
// TestLoaderDropCounts_RingbufReserveFailure: flood a pipe write with
// nothing draining the ring) and asserts that reportDrops — wired to the
// same tinytapSession the CLI builds in bpf.go — prints the summary line.
// #303's unit tests only ever exercise reportDrops against a fakeBPF with a
// hand-set Counts value, so this is the only place the real
// dropCounts→Summary→log.Print wiring gets checked end to end.
func TestReportDrops_RealRingbufDrop(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root / CAP_BPF")
	}

	tt, err := loader.Load(0)
	if err != nil {
		t.Fatalf("loader.Load: %v", err)
	}
	t.Cleanup(func() { _ = tt.Close() })

	sess := &tinytapSession{rd: tt.Reader, closer: tt, drops: tt.DropCounts}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	const maxWrites = 6000
	buf := []byte("x")
	for i := 0; i < maxWrites && sess.dropCounts().Ringbuf == 0; i++ {
		if _, err := w.Write(buf); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if sess.dropCounts().Ringbuf == 0 {
		t.Fatalf("Ringbuf drop count still 0 after %d writes with nothing draining the ring", maxWrites)
	}

	var logBuf bytes.Buffer
	oldOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(oldOut)

	reportDrops(sess, newSSLWatcher(&fakeSink{}))

	got := logBuf.String()
	if !strings.Contains(got, "drops:") {
		t.Fatalf("reportDrops logged %q, want a drops summary for a real ring buffer overflow", got)
	}
	if !strings.Contains(got, "ring buffer full:") {
		t.Fatalf("reportDrops logged %q, want it to attribute the drop to the ring buffer", got)
	}
}
