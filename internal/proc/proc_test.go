package proc_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/proc"
)

// fixture builds a minimal /proc tree under a temp dir and returns its path.
func fixture(t *testing.T, entries map[uint32]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, comm := range entries {
		dir := filepath.Join(root, fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestLookup(t *testing.T) {
	tests := []struct {
		name    string
		entries map[uint32]string
		pid     uint32
		want    string
	}{
		{
			name:    "normal process",
			entries: map[uint32]string{1234: "myapp\n"},
			pid:     1234,
			want:    "myapp",
		},
		{
			name:    "trailing newline stripped",
			entries: map[uint32]string{1: "init\n"},
			pid:     1,
			want:    "init",
		},
		{
			name:    "no trailing newline",
			entries: map[uint32]string{2: "kthreadd"},
			pid:     2,
			want:    "kthreadd",
		},
		{
			name:    "pid 0 kernel thread",
			entries: map[uint32]string{0: "swapper/0\n"},
			pid:     0,
			want:    "swapper/0",
		},
		{
			name:    "long comm name truncated by kernel at 15 chars",
			entries: map[uint32]string{42: "very-long-proce\n"},
			pid:     42,
			want:    "very-long-proce",
		},
		{
			name:    "comm with null byte padding",
			entries: map[uint32]string{99: "app\x00\x00\x00"},
			pid:     99,
			want:    "app",
		},
		{
			name:    "exited process — no entry",
			entries: map[uint32]string{},
			pid:     9999,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fixture(t, tt.entries)
			got := proc.Lookup(root, tt.pid)
			if got != tt.want {
				t.Errorf("Lookup(%d) = %q, want %q", tt.pid, got, tt.want)
			}
		})
	}
}

func TestLookup_DefaultRoot(t *testing.T) {
	// Passing "" uses /proc, which exists on Linux. PID 1 always has a comm.
	got := proc.Lookup("", 1)
	if got == "" {
		t.Error("Lookup(\"\", 1) returned empty; expected a process name from the live /proc")
	}
}

func TestLookup_PermissionDenied(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "777")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	commPath := filepath.Join(dir, "comm")
	if err := os.WriteFile(commPath, []byte("secret\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	// running as root bypasses permission checks, so skip in that case
	if os.Getuid() == 0 {
		t.Skip("running as root: permission-denied test not applicable")
	}
	got := proc.Lookup(root, 777)
	if got != "" {
		t.Errorf("Lookup on unreadable comm = %q, want \"\"", got)
	}
}

func TestLookup_RecycledPID(t *testing.T) {
	// No caching: two consecutive lookups for the same PID return whatever
	// /proc/<pid>/comm contains at that moment. Simulate reuse by changing
	// the file contents between calls.
	root := t.TempDir()
	dir := filepath.Join(root, "500")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	commPath := filepath.Join(dir, "comm")

	if err := os.WriteFile(commPath, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := proc.Lookup(root, 500); got != "first" {
		t.Errorf("first lookup = %q, want \"first\"", got)
	}

	if err := os.WriteFile(commPath, []byte("second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := proc.Lookup(root, 500); got != "second" {
		t.Errorf("second lookup after recycle = %q, want \"second\"", got)
	}
}
