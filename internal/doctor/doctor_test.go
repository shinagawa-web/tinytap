package doctor

import "testing"

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{OK, "OK"},
		{Info, "INFO"},
		{Degraded, "DEGRADED"},
		{Blocking, "BLOCKING"},
		{Severity(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestRun_ReturnsChecksInFixedOrder(t *testing.T) {
	checks := Run()
	if len(checks) == 0 {
		t.Fatal("want at least one check")
	}
	if checks[0].Name != "kernel version" {
		t.Errorf("checks[0].Name = %q, want kernel version (first in Run's fixed order)", checks[0].Name)
	}
}

func TestAnyBlocking(t *testing.T) {
	if AnyBlocking([]Check{{Severity: OK}, {Severity: Degraded}}) {
		t.Error("want false with no Blocking check present")
	}
	if !AnyBlocking([]Check{{Severity: OK}, {Severity: Blocking}}) {
		t.Error("want true with a Blocking check present")
	}
	if AnyBlocking(nil) {
		t.Error("want false for an empty slice")
	}
}
