package doctor

import "fmt"

var (
	loadTinytapObjects = realLoadTinytapObjects
	removeMemlock      = realRemoveMemlock
)

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
