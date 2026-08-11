//go:build amd64 || arm64

package loader

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

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
			"drop_counters":       tt.objs.DropCounters,
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
