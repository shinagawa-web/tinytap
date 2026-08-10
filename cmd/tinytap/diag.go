package main

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

const diagBufferCap = 1000 // keep in sync with internal/output/tui's maxDiagLines

type diagBuffer struct {
	mu     sync.Mutex
	lines  []string
	notify func(string)
	skip   func(string) bool
}

func newDiagBuffer(notify func(string), skip func(string) bool) *diagBuffer {
	return &diagBuffer{notify: notify, skip: skip}
}

func (d *diagBuffer) Write(p []byte) (int, error) {
	line := string(bytes.TrimRight(p, "\n"))
	if d.skip != nil && d.skip(line) {
		return len(p), nil
	}
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

func (d *diagBuffer) Flush(w io.Writer) {
	d.mu.Lock()
	lines := append([]string(nil), d.lines...)
	d.mu.Unlock()
	for _, l := range lines {
		_, _ = fmt.Fprintln(w, l)
	}
}

var _ io.Writer = (*diagBuffer)(nil)
