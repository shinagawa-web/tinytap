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

type TracepointSpec struct {
	Name     string
	Fallback string
}

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
	{Name: "sys_enter_sendfile64", Fallback: "sys_enter_sendfile"},
	{Name: "sys_exit_read"},
	{Name: "sys_exit_recvfrom"},
	{Name: "sys_exit_recvmsg"},
	{Name: "sys_exit_readv"},
	{Name: "sys_exit_sendfile64", Fallback: "sys_exit_sendfile"},
}

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
	if len(progs) != len(Tracepoints) {
		return nil, fmt.Errorf("progs (%d) and Tracepoints (%d) are out of sync: %w",
			len(progs), len(Tracepoints), tt.Close())
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

	tt.tryAttachKprobe()

	rd, err := ringbuf.NewReader(tt.objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf: %w", errors.Join(err, tt.Close()))
	}
	tt.Reader = rd
	tt.readerCloser = rd

	return tt, nil
}
