package loader

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

type Tinytap struct {
	objs             bpf.TinytapObjects
	objsCloser       io.Closer
	kprobeObjsCloser io.Closer
	tracepoints      []io.Closer
	readerCloser     io.Closer
	Reader           *ringbuf.Reader
}

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
	if t.kprobeObjsCloser != nil {
		if err := t.kprobeObjsCloser.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close kprobe objects: %w", err))
		}
	}
	if t.objsCloser != nil {
		if err := t.objsCloser.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close objects: %w", err))
		}
	}
	return errors.Join(errs...)
}
