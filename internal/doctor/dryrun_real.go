package doctor

import (
	"github.com/cilium/ebpf/rlimit"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

func realLoadTinytapObjects() error {
	var objs bpf.TinytapObjects
	if err := bpf.LoadTinytapObjects(&objs, nil); err != nil {
		return err
	}
	return objs.Close()
}

func realRemoveMemlock() error {
	return rlimit.RemoveMemlock()
}
