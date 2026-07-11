//go:build amd64 || arm64

package loader

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

// tryAttachKprobe loads the fentry/tcp_sendmsg_locked kprobe and attaches it.
// The kprobe program derives kernel VAs with arch-specific memory-map bases
// (arm64 constants, x86_64 live KASLR ksyms) and is compiled per target arch
// by bpf2go, so its bindings only exist on amd64 and arm64 — hence this build
// tag.  Every other GOARCH gets the no-op stub in load_kprobe_other.go.
func (tt *Tinytap) tryAttachKprobe() {
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
