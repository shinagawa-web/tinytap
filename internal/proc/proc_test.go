package proc_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/proc"
)

type procEntry struct {
	comm    string
	cmdline string // raw null-separated cmdline bytes; "" means no cmdline file
}

// fixture builds a minimal /proc tree under a temp dir and returns its path.
func fixture(t *testing.T, entries map[uint32]procEntry) string {
	t.Helper()
	root := t.TempDir()
	for pid, e := range entries {
		dir := filepath.Join(root, fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if e.comm != "" {
			if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(e.comm), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if e.cmdline != "" {
			if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(e.cmdline), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func TestLookup(t *testing.T) {
	tests := []struct {
		name    string
		entries map[uint32]procEntry
		pid     uint32
		want    string
	}{
		{
			name:    "normal process",
			entries: map[uint32]procEntry{1234: {comm: "myapp\n"}},
			pid:     1234,
			want:    "myapp",
		},
		{
			name:    "trailing newline stripped",
			entries: map[uint32]procEntry{1: {comm: "init\n"}},
			pid:     1,
			want:    "init",
		},
		{
			name:    "no trailing newline",
			entries: map[uint32]procEntry{2: {comm: "kthreadd"}},
			pid:     2,
			want:    "kthreadd",
		},
		{
			name:    "pid 0 kernel thread",
			entries: map[uint32]procEntry{0: {comm: "swapper/0\n"}},
			pid:     0,
			want:    "swapper/0",
		},
		{
			name:    "long comm name truncated by kernel at 15 chars",
			entries: map[uint32]procEntry{42: {comm: "very-long-proce\n"}},
			pid:     42,
			want:    "very-long-proce",
		},
		{
			name:    "comm with null byte padding",
			entries: map[uint32]procEntry{99: {comm: "app\x00\x00\x00"}},
			pid:     99,
			want:    "app",
		},
		{
			name:    "exited process — no entry",
			entries: map[uint32]procEntry{},
			pid:     9999,
			want:    "",
		},
		{
			name:    "malformed comm with embedded null byte",
			entries: map[uint32]procEntry{55: {comm: "ap\x00p\n"}},
			pid:     55,
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
	if _, err := os.Open("/proc/1/comm"); err != nil {
		t.Skipf("/proc/1/comm not accessible in this environment: %v", err)
	}
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
	if os.Getuid() == 0 {
		t.Skip("running as root: permission-denied test not applicable")
	}
	got := proc.Lookup(root, 777)
	if got != "" {
		t.Errorf("Lookup on unreadable comm = %q, want \"\"", got)
	}
}

func TestLookup_RecycledPID(t *testing.T) {
	// No caching: two consecutive lookups return whatever the file contains at
	// that moment, so a recycled PID never returns a stale name.
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

func TestLookupCmdline(t *testing.T) {
	tests := []struct {
		name    string
		entries map[uint32]procEntry
		pid     uint32
		want    string
	}{
		{
			name:    "single arg (kernel thread / no args)",
			entries: map[uint32]procEntry{1: {cmdline: "init\x00"}},
			pid:     1,
			want:    "init",
		},
		{
			name:    "multiple args",
			entries: map[uint32]procEntry{42: {cmdline: "python3\x00manage.py\x00runserver\x00"}},
			pid:     42,
			want:    "python3 manage.py runserver",
		},
		{
			name:    "no trailing null",
			entries: map[uint32]procEntry{3: {cmdline: "node\x00server.js"}},
			pid:     3,
			want:    "node server.js",
		},
		{
			name:    "exited process — no entry",
			entries: map[uint32]procEntry{},
			pid:     9999,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fixture(t, tt.entries)
			got := proc.LookupCmdline(root, tt.pid)
			if got != tt.want {
				t.Errorf("LookupCmdline(%d) = %q, want %q", tt.pid, got, tt.want)
			}
		})
	}
}

func TestLookupCmdline_DefaultRoot(t *testing.T) {
	if _, err := os.Open("/proc/1/cmdline"); err != nil {
		t.Skipf("/proc/1/cmdline not accessible in this environment: %v", err)
	}
	got := proc.LookupCmdline("", 1)
	if got == "" {
		t.Error("LookupCmdline(\"\", 1) returned empty; expected cmdline from live /proc")
	}
}
