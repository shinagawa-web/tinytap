package main

import (
	"fmt"

	"github.com/shinagawa-web/tinytap/internal/doctor"
)

// doctorRun and doctorRender are injected for testability.
var (
	doctorRun    = doctor.Run
	doctorRender = doctor.Render
)

// runDoctorCmd runs every preflight check (#209) and prints a copy-paste
// friendly report. Read-only and safe to run without privileges — that's
// exactly the case it exists for. Exits non-zero only when a Blocking
// check is present, so `tinytap doctor && tinytap` is a sensible idiom;
// the report itself already explains why, so this returns errSilentExit
// rather than a second error message.
func runDoctorCmd() error {
	checks := doctorRun()
	fmt.Print(doctorRender(checks, versionLine()))
	if doctor.AnyBlocking(checks) {
		return errSilentExit
	}
	return nil
}

// classifyLoadError wraps a raw loadBPF failure with the first Blocking
// preflight cause found, so a startup failure on a machine that never runs
// `tinytap doctor` still reads as e.g. "kernel version: 5.7.0 (>= 5.8
// required): run `tinytap doctor` for the full report" instead of only a
// multi-hundred-line verifier dump or a bare "operation not permitted"
// (#209). Falls back to the raw wrapped error if doctor's checks don't
// explain it — that can happen (a load can fail for a reason doctor
// doesn't check, or the environment has changed between the two calls).
func classifyLoadError(loadErr error) error {
	for _, c := range doctorRun() {
		if c.Severity == doctor.Blocking {
			return fmt.Errorf("%s: %s — run `tinytap doctor` for the full report: %w", c.Name, c.Detail, loadErr)
		}
	}
	return fmt.Errorf("load: %w", loadErr)
}
