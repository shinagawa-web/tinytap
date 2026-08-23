package main

import (
	"fmt"
	"os"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/shinagawa-web/tinytap/internal/doctor"
)

var (
	doctorRun    = doctor.Run
	doctorRender = doctor.Render
)

var (
	degradedLabelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)
	blockingLabelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
)

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

func colorizeDoctorReport(report string) string {
	report = strings.ReplaceAll(report, "[DEGRADED]", degradedLabelStyle.Render("[DEGRADED]"))
	report = strings.ReplaceAll(report, "[BLOCKING]", blockingLabelStyle.Render("[BLOCKING]"))
	return report
}

func classifyLoadError(loadErr error) error {
	for _, c := range doctorRun() {
		if c.Severity == doctor.Blocking {
			return fmt.Errorf("%s: %s — run `tinytap doctor` for the full report: %w", c.Name, c.Detail, loadErr)
		}
	}
	return fmt.Errorf("load: %w", loadErr)
}
