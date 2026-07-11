package loader

import (
	"errors"
	"fmt"
	"log"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

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

	attaches := []struct {
		name     string
		fallback string // alternate tracepoint name tried when name is absent
		prog     *ebpf.Program
	}{
		{"sys_enter_accept4", "", tt.objs.HandleAccept4},
		{"sys_enter_read", "", tt.objs.HandleRead},
		{"sys_enter_write", "", tt.objs.HandleWrite},
		{"sys_enter_close", "", tt.objs.HandleClose},
		{"sys_enter_recvfrom", "", tt.objs.HandleRecvfrom},
		{"sys_enter_sendto", "", tt.objs.HandleSendto},
		{"sys_enter_recvmsg", "", tt.objs.HandleRecvmsg},
		{"sys_enter_sendmsg", "", tt.objs.HandleSendmsg},
		{"sys_enter_writev", "", tt.objs.HandleWritev},
		{"sys_enter_readv", "", tt.objs.HandleReadv},
		// sendfile tracepoint name varies by kernel: most expose sendfile64,
		// but some kernels (older or with different config) expose sendfile.
		{"sys_enter_sendfile64", "sys_enter_sendfile", tt.objs.HandleSendfile},
		{"sys_exit_read", "", tt.objs.HandleExitRead},
		{"sys_exit_recvfrom", "", tt.objs.HandleExitRecvfrom},
		{"sys_exit_recvmsg", "", tt.objs.HandleExitRecvmsg},
		{"sys_exit_readv", "", tt.objs.HandleExitReadv},
		{"sys_exit_sendfile64", "sys_exit_sendfile", tt.objs.HandleExitSendfile},
	}
	for _, a := range attaches {
		tp, err := link.Tracepoint("syscalls", a.name, a.prog, nil)
		if err != nil && a.fallback != "" {
			tp, err = link.Tracepoint("syscalls", a.fallback, a.prog, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("attach %s: %w", a.name, errors.Join(err, tt.Close()))
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

// tryAttachKprobe attempts to load the companion kprobe BPF object and
// attach its fentry/tcp_sendmsg_locked program.  Any failure is logged and
// silently ignored — the main capture continues without payload bytes for
// sendfile events.
func (tt *Tinytap) tryAttachKprobe() {
	// The kprobe program derives kernel VAs with arch-specific memory-map
	// bases (arm64 constants, x86_64 live KASLR ksyms), compiled per target
	// arch by bpf2go.  Only these two arches are supported; skip silently on
	// anything else rather than reading garbage page addresses.
	switch runtime.GOARCH {
	case "arm64", "amd64":
	default:
		log.Printf("tinytap: kprobe sendfile payload capture is arm64/amd64-only, skipping on %s", runtime.GOARCH)
		return
	}

	kprobeSpec, err := bpf.LoadTinytapKprobe()
	if err != nil {
		log.Printf("tinytap: kprobe load spec: %v (sendfile payload capture disabled)", err)
		return
	}

	kprobeObjs := new(bpf.TinytapKprobeObjects)
	err = kprobeSpec.LoadAndAssign(kprobeObjs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"sendfile_sample_map": tt.objs.SendfileSampleMap,
		},
	})
	if err != nil {
		_ = kprobeObjs.Close()
		log.Printf("tinytap: kprobe load objects: %v (sendfile payload capture disabled)", err)
		return
	}

	lnk, err := link.AttachTracing(link.TracingOptions{
		Program:    kprobeObjs.HandleTcpSendmsgLocked,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		_ = kprobeObjs.Close()
		log.Printf("tinytap: attach fentry/tcp_sendmsg_locked: %v (sendfile payload capture disabled)", err)
		return
	}

	tt.tracepoints = append(tt.tracepoints, lnk)
	tt.kprobeObjsCloser = kprobeObjs
}
