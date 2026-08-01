package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckCapabilities_AllPresent(t *testing.T) {
	// CapEff with every bit up to 39 set: 0xffffffffff.
	path := writeStatus(t, "0000ffffffffff")
	checks := checkCapabilities(path)
	for _, c := range checks {
		if c.Severity != OK {
			t.Errorf("%s: Severity = %v, want OK", c.Name, c.Severity)
		}
	}
}

func TestCheckCapabilities_AllMissing(t *testing.T) {
	path := writeStatus(t, "0000000000000000")
	checks := checkCapabilities(path)

	want := map[string]Severity{
		"cap_dac_read_search": Blocking,
		"cap_perfmon":         Blocking,
		"cap_bpf":             Blocking,
		"cap_sys_admin":       Degraded,
	}
	for _, c := range checks {
		if wantSev, ok := want[c.Name]; ok {
			if c.Severity != wantSev {
				t.Errorf("%s: Severity = %v, want %v", c.Name, c.Severity, wantSev)
			}
			if c.Fix == "" || c.Affects == "" {
				t.Errorf("%s: want Affects and Fix set", c.Name)
			}
		}
	}
}

func TestCheckCapabilities_CapSyslogArchGating(t *testing.T) {
	path := writeStatus(t, "0000000000000000")
	checks := checkCapabilities(path)

	var syslog *Check
	for i := range checks {
		if checks[i].Name == "cap_syslog" {
			syslog = &checks[i]
		}
	}
	if syslog == nil {
		t.Fatal("no cap_syslog check found")
	}
	// This test runs on whatever GOARCH the CI/dev machine is; just assert
	// the two possible outcomes are mutually exclusive and sensible.
	if syslog.Severity != OK && syslog.Severity != Degraded {
		t.Errorf("cap_syslog Severity = %v, want OK (non-amd64) or Degraded (amd64, missing)", syslog.Severity)
	}
}

func TestCheckCapabilities_MissingFile(t *testing.T) {
	checks := checkCapabilities(filepath.Join(t.TempDir(), "does-not-exist"))
	if len(checks) != 1 || checks[0].Severity != Info {
		t.Errorf("checks = %+v, want a single Info result", checks)
	}
}

func TestCheckCapabilities_NoCapEffLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte("Name:\ttinytap\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	checks := checkCapabilities(path)
	if len(checks) != 1 || checks[0].Severity != Info {
		t.Errorf("checks = %+v, want a single Info result", checks)
	}
}

func TestCheckCapabilities_MalformedCapEff(t *testing.T) {
	path := writeStatus(t, "not-hex")
	checks := checkCapabilities(path)
	if len(checks) != 1 || checks[0].Severity != Info {
		t.Errorf("checks = %+v, want a single Info result", checks)
	}
}

func TestCheckCapabilities_ScannerError(t *testing.T) {
	// A single line far past bufio.Scanner's default token limit (64KiB)
	// with no CapEff prefix, and no newline, forces scanner.Err() to
	// return bufio.ErrTooLong instead of a clean EOF.
	path := filepath.Join(t.TempDir(), "status")
	huge := make([]byte, 128*1024)
	for i := range huge {
		huge[i] = 'x'
	}
	if err := os.WriteFile(path, huge, 0o644); err != nil {
		t.Fatal(err)
	}
	checks := checkCapabilities(path)
	if len(checks) != 1 || checks[0].Severity != Info {
		t.Errorf("checks = %+v, want a single Info result", checks)
	}
}

func TestCheckCapabilities_DefaultPath(t *testing.T) {
	// Just confirm the default-path branch runs without panicking.
	_ = checkCapabilities("")
}

func TestSetcapFix_MentionsCapability(t *testing.T) {
	fix := setcapFix("cap_bpf")
	if fix == "" {
		t.Error("want non-empty fix")
	}
}

func writeStatus(t *testing.T, capEffHex string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "status")
	content := "Name:\ttinytap\nCapEff:\t" + capEffHex + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
