package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/shinagawa-web/tinytap/internal/doctor"
)

// doctorRun and doctorRender are injected for testability.
var (
	doctorRun    = doctor.Run
	doctorRender = doctor.Render
)

// degradedLabelStyle/blockingLabelStyle color runDoctorCmd's terminal-only
// output (see colorizeDoctorReport). Yellow for Degraded matches the TUI's
// existing warning convention (slowLatencyStyle / the diag footer
// indicator, #248); Blocking gets red as the more severe case.
var (
	degradedLabelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)
	blockingLabelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
)

// runDoctorCmd runs every preflight check (#209) and prints a copy-paste
// friendly report. Read-only and safe to run without privileges — that's
// exactly the case it exists for. Exits non-zero only when a Blocking
// check is present, so `tinytap doctor && tinytap` is a sensible idiom;
// the report itself already explains why, so this returns errSilentExit
// rather than a second error message.
func runDoctorCmd() error {
	checks := doctorRun()
	report := doctorRender(checks, versionLine())
	if isTerminalFn(int(os.Stdout.Fd())) {
		report = colorizeDoctorReport(report)
	}
	fmt.Print(report)
	if doctor.AnyBlocking(checks) {
		return errSilentExit
	}
	return nil
}

// colorizeDoctorReport highlights the DEGRADED/BLOCKING severity labels in
// an already-rendered report — called only when stdout is a terminal.
// doctor.Render's own output must stay plain text (its doc comment calls it
// out as copy-paste-friendly for bug reports), so color is layered on here
// rather than inside the doctor package, and only for the terminal path; a
// piped or redirected `tinytap doctor` never sees escape codes. Matching on
// the literal "[DEGRADED]"/"[BLOCKING]" tokens works because Render's
// "%-8s" padding is a no-op for both — they're exactly 8 characters.
func colorizeDoctorReport(report string) string {
	report = strings.ReplaceAll(report, "[DEGRADED]", degradedLabelStyle.Render("[DEGRADED]"))
	report = strings.ReplaceAll(report, "[BLOCKING]", blockingLabelStyle.Render("[BLOCKING]"))
	return report
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
