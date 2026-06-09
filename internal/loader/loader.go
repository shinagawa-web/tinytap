// Package loader owns the BPF program lifecycle: lock memory, load the
// generated bindings, attach every tracepoint the program declares, and
// expose a ringbuf.Reader for userspace consumption. Callers see this as
// "give me an attached, running BPF and a Reader to drain it" — they
// never touch cilium/ebpf directly.
package loader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

// Tinytap owns the loaded BPF objects, the tracepoint attachments, and
// the ringbuf reader. Close releases everything in the reverse order it
// was set up.
type Tinytap struct {
	objs        bpf.TinytapObjects
	tracepoints []link.Link
	// Reader drains the BPF ringbuf. Each record is the raw bytes of a
	// `struct event` (see internal/events.Event for the matching Go type).
	Reader *ringbuf.Reader
}

// Load locks memory, loads the BPF spec, sets the `own_pid` variable so
// the BPF side can skip events from this process (and avoid a logging
// feedback loop), attaches all tracepoints, and opens the ringbuf. On
// any failure it tears down what it already set up before returning.
func Load(ownPid uint32) (*Tinytap, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := bpf.LoadTinytap()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	if err := spec.Variables["own_pid"].Set(ownPid); err != nil {
		return nil, fmt.Errorf("set own_pid: %w", err)
	}

	tt := &Tinytap{}
	if err := spec.LoadAndAssign(&tt.objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}

	attaches := []struct {
		name string
		prog *ebpf.Program
	}{
		{"sys_enter_accept4", tt.objs.HandleAccept4},
		{"sys_enter_read", tt.objs.HandleRead},
		{"sys_enter_write", tt.objs.HandleWrite},
		{"sys_enter_close", tt.objs.HandleClose},
		{"sys_enter_recvfrom", tt.objs.HandleRecvfrom},
		{"sys_enter_sendto", tt.objs.HandleSendto},
		{"sys_enter_recvmsg", tt.objs.HandleRecvmsg},
		{"sys_enter_sendmsg", tt.objs.HandleSendmsg},
		{"sys_exit_read", tt.objs.HandleExitRead},
		{"sys_exit_recvfrom", tt.objs.HandleExitRecvfrom},
		{"sys_exit_recvmsg", tt.objs.HandleExitRecvmsg},
	}
	for _, a := range attaches {
		tp, err := link.Tracepoint("syscalls", a.name, a.prog, nil)
		if err != nil {
			tt.Close()
			return nil, fmt.Errorf("attach %s: %w", a.name, err)
		}
		tt.tracepoints = append(tt.tracepoints, tp)
	}

	rd, err := ringbuf.NewReader(tt.objs.Events)
	if err != nil {
		tt.Close()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	tt.Reader = rd

	return tt, nil
}

// Close detaches every tracepoint, closes the ringbuf reader, and
// releases the loaded BPF objects. Safe to call on a partially
// initialised Tinytap (after a failed Load). All teardown errors are
// joined and returned so a single failing component doesn't silently
// hide its sibling's failures.
func (t *Tinytap) Close() error {
	var errs []error
	if t.Reader != nil {
		if err := t.Reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close ringbuf reader: %w", err))
		}
	}
	for i, tp := range t.tracepoints {
		if err := tp.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close tracepoint %d: %w", i, err))
		}
	}
	if err := t.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close objects: %w", err))
	}
	return errors.Join(errs...)
}
