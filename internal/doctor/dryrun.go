package doctor

import "fmt"

// loadTinytapObjects and removeMemlock are injected so tests can force
// success/failure without needing real eBPF privileges; their default
// (production) implementations live in dryrun_real.go.
var (
	loadTinytapObjects = realLoadTinytapObjects
	removeMemlock      = realRemoveMemlock
)

// checkDryRunLoad attempts to load (but not attach) the main BPF object —
// the same step loader.Load performs first. Unlike the capability checks,
// which predict whether this step should succeed, this actually attempts
// it: a verifier rejection or a bad build (see #207's clang-14 finding)
// would pass every capability check yet still fail here.
func checkDryRunLoad() Check {
	if err := removeMemlock(); err != nil {
		return Check{Name: "BPF dry-run load", Severity: Blocking, Detail: fmt.Sprintf("remove memlock: %v", err),
			Affects: "Everything — this is the first step tinytap's real startup performs.",
			Fix:     "run with the capabilities listed at https://shinagawa-web.github.io/tinytap/docs/running-without-root/, or as root"}
	}
	if err := loadTinytapObjects(); err != nil {
		return Check{
			Name:     "BPF dry-run load",
			Severity: Blocking,
			Detail:   err.Error(),
			Affects:  "Everything — this is the exact load step tinytap's real startup performs.",
			Fix:      "if the checks above are all OK, this is likely a verifier rejection or a build problem, not a missing prerequisite — file a bug report with this doctor output attached",
		}
	}
	return Check{Name: "BPF dry-run load", Severity: OK, Detail: "loaded and verified cleanly"}
}
