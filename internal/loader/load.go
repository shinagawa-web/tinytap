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

// TracepointSpec names one syscalls tracepoint Load attaches to, plus an
// optional fallback name tried when the primary one doesn't exist on this
// kernel (see the sendfile/sendfile64 comment below).
type TracepointSpec struct {
	Name     string
	Fallback string
}

// Tracepoints is the exact list Load attaches, in attach order — exported
// so internal/doctor's preflight check can confirm each one exists under
// /sys/kernel/tracing/events/syscalls/ without duplicating (and risking
// drift from) this list.
var Tracepoints = []TracepointSpec{
	{Name: "sys_enter_accept4"},
	{Name: "sys_enter_read"},
	{Name: "sys_enter_write"},
	{Name: "sys_enter_close"},
	{Name: "sys_enter_recvfrom"},
	{Name: "sys_enter_sendto"},
	{Name: "sys_enter_recvmsg"},
	{Name: "sys_enter_sendmsg"},
	{Name: "sys_enter_writev"},
	{Name: "sys_enter_readv"},
	// sendfile tracepoint name varies by kernel: most expose sendfile64,
	// but some kernels (older or with different config) expose sendfile.
	{Name: "sys_enter_sendfile64", Fallback: "sys_enter_sendfile"},
	{Name: "sys_exit_read"},
	{Name: "sys_exit_recvfrom"},
	{Name: "sys_exit_recvmsg"},
	{Name: "sys_exit_readv"},
	{Name: "sys_exit_sendfile64", Fallback: "sys_exit_sendfile"},
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
	tt.objsCloser = &tt.objs
	if err := spec.LoadAndAssign(&tt.objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}

	progs := []*ebpf.Program{
		tt.objs.HandleAccept4,
		tt.objs.HandleRead,
		tt.objs.HandleWrite,
		tt.objs.HandleClose,
		tt.objs.HandleRecvfrom,
		tt.objs.HandleSendto,
		tt.objs.HandleRecvmsg,
		tt.objs.HandleSendmsg,
		tt.objs.HandleWritev,
		tt.objs.HandleReadv,
		tt.objs.HandleSendfile,
		tt.objs.HandleExitRead,
		tt.objs.HandleExitRecvfrom,
		tt.objs.HandleExitRecvmsg,
		tt.objs.HandleExitReadv,
		tt.objs.HandleExitSendfile,
	}
	for i, tpSpec := range Tracepoints {
		tp, err := link.Tracepoint("syscalls", tpSpec.Name, progs[i], nil)
		if err != nil && tpSpec.Fallback != "" {
			tp, err = link.Tracepoint("syscalls", tpSpec.Fallback, progs[i], nil)
		}
		if err != nil {
			return nil, fmt.Errorf("attach %s: %w", tpSpec.Name, errors.Join(err, tt.Close()))
		}
		tt.tracepoints = append(tt.tracepoints, tp)
	}

	// Optionally load the fentry/tcp_sendmsg_locked kprobe that captures
	// page-cache bytes during sendfile.  If BTF or fentry is unavailable
	// (kernel < 5.5, or no BTF), sendfile events still work — they just
	// carry no payload bytes.
	tt.tryAttachKprobe()

	rd, err := ringbuf.NewReader(tt.objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf: %w", errors.Join(err, tt.Close()))
	}
	tt.Reader = rd
	tt.readerCloser = rd

	return tt, nil
}

// tryAttachKprobe attempts to load the companion kprobe BPF object and attach
// its fentry/tcp_sendmsg_locked program.  Its implementation is arch-specific:
// the sendfile page->VA derivation only has arm64 and amd64 support, and the
// bpf2go-generated kprobe bindings only exist for those arches, so the real
// implementation lives in load_kprobe.go (amd64 || arm64) and a no-op stub in
// load_kprobe_other.go covers every other GOARCH.  Any failure is logged and
// silently ignored — the main capture continues without payload bytes for
// sendfile events.
