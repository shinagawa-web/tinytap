package doctor

import (
	"github.com/cilium/ebpf/rlimit"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

// realLoadTinytapObjects attempts the exact load step loader.Load performs
// (minus attaching), then immediately releases everything. Like
// internal/loader/load.go, fully exercising both its success and failure
// paths needs real eBPF privileges, so this file is excluded from the
// 100% coverage requirement (Makefile's check-coverage target) the same
// way load.go and its kprobe/uprobe siblings already are.
func realLoadTinytapObjects() error {
	var objs bpf.TinytapObjects
	if err := bpf.LoadTinytapObjects(&objs, nil); err != nil {
		return err
	}
	return objs.Close()
}

// realRemoveMemlock is rlimit.RemoveMemlock, aliased so checkDryRunLoad's
// removeMemlock var has a named default (see dryrun.go).
func realRemoveMemlock() error {
	return rlimit.RemoveMemlock()
}
