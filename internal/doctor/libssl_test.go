package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseLdconfigLibSSLPaths(t *testing.T) {
	out := "\tlibssl3.so (libc6,AArch64) => /lib/aarch64-linux-gnu/libssl3.so\n" +
		"\tlibssl.so.3 (libc6,AArch64) => /lib/aarch64-linux-gnu/libssl.so.3\n" +
		"\tlibc.so.6 (libc6,AArch64) => /lib/aarch64-linux-gnu/libc.so.6\n"

	// libssl3.so intentionally doesn't match: internal/tls.Find's
	// per-process detection only recognizes /libssl\.so(\.N)*$ (see
	// libsslPattern in internal/tls/discover.go), so doctor's host-level
	// check uses the identical pattern for consistency.
	got := parseLdconfigLibSSLPaths(out)
	want := []string{"/lib/aarch64-linux-gnu/libssl.so.3"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseLdconfigLibSSLPaths_NoMatches(t *testing.T) {
	if got := parseLdconfigLibSSLPaths("\tlibc.so.6 => /lib/libc.so.6\n"); len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestCheckLibSSL_LdconfigError(t *testing.T) {
	old := runLdconfig
	runLdconfig = func() (string, error) { return "", errors.New("not found") }
	defer func() { runLdconfig = old }()

	c := checkLibSSL()
	if c.Severity != Info {
		t.Errorf("Severity = %v, want Info", c.Severity)
	}
}

func TestCheckLibSSL_NoneFound(t *testing.T) {
	old := runLdconfig
	runLdconfig = func() (string, error) { return "\tlibc.so.6 => /lib/libc.so.6\n", nil }
	defer func() { runLdconfig = old }()

	c := checkLibSSL()
	if c.Severity != Info {
		t.Errorf("Severity = %v, want Info", c.Severity)
	}
}

func TestCheckLibSSL_ExecutableFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "libssl.so.3")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	old := runLdconfig
	runLdconfig = func() (string, error) { return "\tlibssl.so.3 => " + path + "\n", nil }
	defer func() { runLdconfig = old }()

	c := checkLibSSL()
	if c.Severity != OK {
		t.Errorf("Severity = %v, want OK", c.Severity)
	}
}

func TestCheckLibSSL_NotExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "libssl.so.3")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	old := runLdconfig
	runLdconfig = func() (string, error) { return "\tlibssl.so.3 => " + path + "\n", nil }
	defer func() { runLdconfig = old }()

	c := checkLibSSL()
	if c.Severity != Degraded {
		t.Errorf("Severity = %v, want Degraded", c.Severity)
	}
	if c.Fix == "" || c.Affects == "" {
		t.Error("want Affects and Fix set")
	}
}

func TestCheckLibSSL_ListedButMissingOnDisk(t *testing.T) {
	// ldconfig's cache lists a stale path that no longer exists — should be
	// skipped, not treated as an error, and fall through to the next
	// candidate (or "not found" if it was the only one).
	stale := filepath.Join(t.TempDir(), "gone", "libssl.so.3")

	old := runLdconfig
	runLdconfig = func() (string, error) { return "\tlibssl.so.3 => " + stale + "\n", nil }
	defer func() { runLdconfig = old }()

	c := checkLibSSL()
	if c.Severity != Info {
		t.Errorf("Severity = %v, want Info (every candidate was stale, nothing was actually checked)", c.Severity)
	}
}
