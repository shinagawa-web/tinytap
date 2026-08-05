package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/shinagawa-web/tinytap/internal/loader"
)

func tracepointNamesForTest() []string {
	names := make([]string, len(loader.Tracepoints))
	for i, tp := range loader.Tracepoints {
		names[i] = tp.Name
	}
	return names
}

func TestCheckSysctls_ReadsValues(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc/sys/kernel/perf_event_paranoid"), "4\n")
	writeFile(t, filepath.Join(root, "proc/sys/kernel/unprivileged_bpf_disabled"), "2\n")

	checks := checkSysctls(root)
	if len(checks) != 2 {
		t.Fatalf("got %d checks, want 2", len(checks))
	}
	if checks[0].Detail != "4" || checks[1].Detail != "2" {
		t.Errorf("checks = %+v", checks)
	}
	for _, c := range checks {
		if c.Severity != Info {
			t.Errorf("%s: Severity = %v, want Info", c.Name, c.Severity)
		}
	}
}

func TestCheckSysctls_MissingFile(t *testing.T) {
	checks := checkSysctls(t.TempDir())
	for _, c := range checks {
		if c.Severity != Info {
			t.Errorf("%s: Severity = %v, want Info even when unreadable", c.Name, c.Severity)
		}
	}
}

func TestCheckSysctls_DefaultRoot(t *testing.T) {
	_ = checkSysctls("")
}

func TestCheckMemlockRlimit(t *testing.T) {
	c := checkMemlockRlimit()
	if c.Severity != Info {
		t.Errorf("Severity = %v, want Info", c.Severity)
	}
	if c.Detail == "" {
		t.Error("want non-empty Detail")
	}
}

func TestRlimitString(t *testing.T) {
	if got := rlimitString(1 << 63); got == "" {
		t.Error("want non-empty for a large finite value")
	}
	if got := rlimitString(^uint64(0)); got != "unlimited" {
		t.Errorf("rlimitString(RLIM_INFINITY) = %q, want unlimited", got)
	}
}

func TestCheckTracepoints_AllPresent(t *testing.T) {
	root := t.TempDir()
	for _, tp := range tracepointNamesForTest() {
		writeFile(t, filepath.Join(root, "events/syscalls", tp, "id"), "1\n")
	}
	c := checkTracepoints(root)
	if c.Severity != OK {
		t.Errorf("Severity = %v, want OK; Detail=%s", c.Severity, c.Detail)
	}
}

func TestCheckTracepoints_FallbackSatisfies(t *testing.T) {
	root := t.TempDir()
	for _, tp := range tracepointNamesForTest() {
		if tp == "sys_enter_sendfile64" {
			continue // only create its fallback
		}
		writeFile(t, filepath.Join(root, "events/syscalls", tp, "id"), "1\n")
	}
	writeFile(t, filepath.Join(root, "events/syscalls/sys_enter_sendfile/id"), "1\n")

	c := checkTracepoints(root)
	if c.Severity != OK {
		t.Errorf("Severity = %v, want OK when the fallback exists; Detail=%s", c.Severity, c.Detail)
	}
}

func TestCheckTracepoints_Missing(t *testing.T) {
	c := checkTracepoints(t.TempDir())
	if c.Severity != Blocking {
		t.Errorf("Severity = %v, want Blocking", c.Severity)
	}
	if c.Fix == "" || c.Affects == "" {
		t.Error("want Affects and Fix set")
	}
}

func TestCheckTracepoints_DefaultRoots(t *testing.T) {
	_ = checkTracepoints("")
}

func TestCheckArch(t *testing.T) {
	c := checkArch()
	if c.Severity != OK && c.Severity != Degraded {
		t.Errorf("Severity = %v, want OK or Degraded", c.Severity)
	}
	if c.Detail == "" {
		t.Error("want non-empty Detail")
	}
}

func TestCheckArchFor_Supported(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		if c := checkArchFor(arch); c.Severity != OK {
			t.Errorf("checkArchFor(%q).Severity = %v, want OK", arch, c.Severity)
		}
	}
}

func TestCheckArchFor_Unsupported(t *testing.T) {
	c := checkArchFor("riscv64")
	if c.Severity != Degraded {
		t.Errorf("Severity = %v, want Degraded", c.Severity)
	}
	if c.Affects == "" {
		t.Error("want Affects set")
	}
}

func TestCheckMemlockRlimit_Error(t *testing.T) {
	old := getrlimitFn
	getrlimitFn = func(int, *unix.Rlimit) error { return errors.New("boom") }
	defer func() { getrlimitFn = old }()

	c := checkMemlockRlimit()
	if c.Severity != Info {
		t.Errorf("Severity = %v, want Info", c.Severity)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
