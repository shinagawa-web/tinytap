package doctor

import (
	"strings"
	"testing"
)

func TestRender_IncludesVersionHeader(t *testing.T) {
	out := Render(nil, "tinytap v0.6.1 (commit abc, built today)")
	if !strings.Contains(out, "tinytap v0.6.1 (commit abc, built today)") {
		t.Errorf("Render output missing version header: %q", out)
	}
}

func TestRender_ChecksAndSummary(t *testing.T) {
	checks := []Check{
		{Name: "kernel version", Severity: OK, Detail: "6.17.0"},
		{Name: "cap_sys_admin", Severity: Degraded, Detail: "missing", Affects: "TLS only", Fix: "setcap ..."},
		{Name: "syscall tracepoints", Severity: Blocking, Detail: "missing: foo", Affects: "everything", Fix: "check kernel config"},
		{Name: "perf_event_paranoid", Severity: Info, Detail: "4"},
	}
	out := Render(checks, "tinytap dev")

	for _, want := range []string{
		"kernel version", "6.17.0",
		"cap_sys_admin", "Affects: TLS only", "Fix:     setcap ...",
		"syscall tracepoints", "Affects: everything", "Fix:     check kernel config",
		"perf_event_paranoid", "4",
		"1 ok, 1 degraded, 1 blocking, 1 info",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Render output missing %q:\n%s", want, out)
		}
	}
}

func TestRender_OKCheckHasNoAffectsOrFixLines(t *testing.T) {
	out := Render([]Check{{Name: "kernel version", Severity: OK, Detail: "6.17.0"}}, "tinytap dev")
	if strings.Contains(out, "Affects:") || strings.Contains(out, "Fix:") {
		t.Errorf("OK check should not print Affects/Fix lines:\n%s", out)
	}
}
