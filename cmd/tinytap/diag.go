package main

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

// diagBufferCap bounds how many diagnostic lines diagBuffer retains during a
// TUI session — generous for realistic TLS-attach chatter (a handful of
// lines per process), small enough to never matter for memory.
const diagBufferCap = 500

// diagBuffer is an io.Writer that captures log lines instead of discarding
// them (#216): log.SetOutput points here during the TUI session so a stray
// log.Printf can never corrupt the alt-screen, but its content survives —
// forwarded to notify (typically tui.Sink.SendDiag, so it can show up in the
// TUI's diagnostics panel) and available for Flush once the session ends.
type diagBuffer struct {
	mu     sync.Mutex
	lines  []string
	notify func(string)
}

func newDiagBuffer(notify func(string)) *diagBuffer {
	return &diagBuffer{notify: notify}
}

// Write implements io.Writer. The log package calls Output once per
// Print/Printf, with the full formatted line already in p, so no splitting
// is needed — just trim the trailing newline log always appends.
func (d *diagBuffer) Write(p []byte) (int, error) {
	line := string(bytes.TrimRight(p, "\n"))
	d.mu.Lock()
	if len(d.lines) < diagBufferCap {
		d.lines = append(d.lines, line)
	} else {
		copy(d.lines, d.lines[1:])
		d.lines[diagBufferCap-1] = line
	}
	d.mu.Unlock()
	if d.notify != nil {
		d.notify(line)
	}
	return len(p), nil
}

// Flush writes every captured line to w, one per line — called after the TUI
// exits so a user who never opened the diagnostics panel still learns why,
// say, HTTPS traffic never appeared, and so the lines are pasteable into a
// bug report.
func (d *diagBuffer) Flush(w io.Writer) {
	d.mu.Lock()
	lines := append([]string(nil), d.lines...)
	d.mu.Unlock()
	for _, l := range lines {
		_, _ = fmt.Fprintln(w, l)
	}
}

var _ io.Writer = (*diagBuffer)(nil)
