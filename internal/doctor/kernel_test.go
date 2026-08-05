package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCheckKernelVersion_OK(t *testing.T) {
	c := checkKernelVersion("6.17.0-41-generic")
	if c.Severity != OK {
		t.Errorf("Severity = %v, want OK", c.Severity)
	}
}

func TestCheckKernelVersion_Boundary(t *testing.T) {
	c := checkKernelVersion("5.8.0")
	if c.Severity != OK {
		t.Errorf("Severity = %v, want OK at the exact floor", c.Severity)
	}
}

func TestCheckKernelVersion_TooOld(t *testing.T) {
	c := checkKernelVersion("5.7.0")
	if c.Severity != Blocking {
		t.Errorf("Severity = %v, want Blocking", c.Severity)
	}
	if c.Fix == "" || c.Affects == "" {
		t.Error("want Affects and Fix set for a Blocking check")
	}
}

func TestCheckKernelVersion_MajorTooOld(t *testing.T) {
	c := checkKernelVersion("4.19.0")
	if c.Severity != Blocking {
		t.Errorf("Severity = %v, want Blocking", c.Severity)
	}
}

func TestCheckKernelVersion_Unparseable(t *testing.T) {
	c := checkKernelVersion("not-a-version")
	if c.Severity != Info {
		t.Errorf("Severity = %v, want Info", c.Severity)
	}
}

func TestCheckKernelVersion_RealUname(t *testing.T) {
	c := checkKernelVersion("")
	if c.Name != "kernel version" {
		t.Errorf("Name = %q", c.Name)
	}
	if c.Severity != OK {
		t.Errorf("Severity = %v, want OK on the CI/dev kernel", c.Severity)
	}
}

func TestCheckKernelVersion_UnameError(t *testing.T) {
	old := unameFn
	unameFn = func(*unix.Utsname) error { return errors.New("boom") }
	defer func() { unameFn = old }()

	c := checkKernelVersion("")
	if c.Severity != Info {
		t.Errorf("Severity = %v, want Info", c.Severity)
	}
}

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		release   string
		wantMajor int
		wantMinor int
		wantOK    bool
	}{
		{"6.17.0-41-generic", 6, 17, true},
		{"5.8.0", 5, 8, true},
		{"5.8", 5, 8, true},
		{"6", 0, 0, false},
		{"", 0, 0, false},
		{"a.b.c", 0, 0, false},
		{"6.17-rc1", 6, 17, true},
		{"6.abc.0", 0, 0, false}, // minor field starts non-digit: strips to "", Atoi fails
	}
	for _, tt := range tests {
		major, minor, ok := parseKernelVersion(tt.release)
		if major != tt.wantMajor || minor != tt.wantMinor || ok != tt.wantOK {
			t.Errorf("parseKernelVersion(%q) = (%d, %d, %v), want (%d, %d, %v)",
				tt.release, major, minor, ok, tt.wantMajor, tt.wantMinor, tt.wantOK)
		}
	}
}

func TestCharsToString(t *testing.T) {
	if got := charsToString([]byte{'a', 'b', 'c', 0, 0}); got != "abc" {
		t.Errorf("charsToString with trailing NUL = %q, want abc", got)
	}
	if got := charsToString([]byte{'x', 'y', 'z'}); got != "xyz" {
		t.Errorf("charsToString with no NUL = %q, want xyz", got)
	}
	if got := charsToString(nil); got != "" {
		t.Errorf("charsToString(nil) = %q, want empty", got)
	}
}

func TestCheckBTF_Present(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vmlinux")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := checkBTF(path)
	if c.Severity != OK {
		t.Errorf("Severity = %v, want OK", c.Severity)
	}
}

func TestCheckBTF_Missing(t *testing.T) {
	c := checkBTF(filepath.Join(t.TempDir(), "does-not-exist"))
	if c.Severity != Degraded {
		t.Errorf("Severity = %v, want Degraded", c.Severity)
	}
	if c.Affects == "" || c.Fix == "" {
		t.Error("want Affects and Fix set for a Degraded check")
	}
}

func TestCheckBTF_DefaultPath(t *testing.T) {
	// Just confirm the default-path branch runs without panicking; the
	// real /sys/kernel/btf/vmlinux may or may not exist on the test host.
	_ = checkBTF("")
}
