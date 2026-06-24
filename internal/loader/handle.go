// Package loader owns the BPF program lifecycle: lock memory, load the
// generated bindings, attach every tracepoint the program declares, and
// expose a ringbuf.Reader for userspace consumption. Callers see this as
// "give me an attached, running BPF and a Reader to drain it" — they
// never touch cilium/ebpf directly.
package loader

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

// Tinytap owns the loaded BPF objects, the tracepoint attachments, and
// the ringbuf reader. Close releases everything in the reverse order it
// was set up.
type Tinytap struct {
	objs         bpf.TinytapObjects
	objsCloser   io.Closer // &objs at runtime; injectable in tests
	tracepoints  []io.Closer
	readerCloser io.Closer // Reader at runtime; injectable in tests
	// Reader drains the BPF ringbuf. Each record is the raw bytes of a
	// `struct event` (see internal/events.Event for the matching Go type).
	Reader *ringbuf.Reader
}

// Close detaches every tracepoint, closes the ringbuf reader, and
// releases the loaded BPF objects. Safe to call on a partially
// initialised Tinytap (after a failed Load). All teardown errors are
// joined and returned so a single failing component doesn't silently
// hide its sibling's failures.
func (t *Tinytap) Close() error {
	var errs []error
	if t.readerCloser != nil {
		if err := t.readerCloser.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close ringbuf reader: %w", err))
		}
	}
	for i, tp := range t.tracepoints {
		if err := tp.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close tracepoint %d: %w", i, err))
		}
	}
	if t.objsCloser != nil {
		if err := t.objsCloser.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close objects: %w", err))
		}
	}
	return errors.Join(errs...)
}
