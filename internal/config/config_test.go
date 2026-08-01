package config

import (
	"os"
	"path/filepath"
	"testing"
)

// --- find ---

func TestFind_CwdCandidate(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "tinytap.toml"), "output = \"stdout\"\n")

	got := find(dir, "", "")
	want := filepath.Join(dir, "tinytap.toml")
	if got != want {
		t.Errorf("find() = %q, want %q", got, want)
	}
}

func TestFind_XDGCandidate(t *testing.T) {
	cwd := t.TempDir()
	xdg := t.TempDir()
	write(t, filepath.Join(xdg, "tinytap", "config.toml"), "output = \"stdout\"\n")

	got := find(cwd, xdg, "")
	want := filepath.Join(xdg, "tinytap", "config.toml")
	if got != want {
		t.Errorf("find() = %q, want %q", got, want)
	}
}

func TestFind_HomeFallback(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	write(t, filepath.Join(home, ".config", "tinytap", "config.toml"), "output = \"stdout\"\n")

	got := find(cwd, "", home)
	want := filepath.Join(home, ".config", "tinytap", "config.toml")
	if got != want {
		t.Errorf("find() = %q, want %q", got, want)
	}
}

func TestFind_CwdWinsOverXDG(t *testing.T) {
	cwd := t.TempDir()
	xdg := t.TempDir()
	write(t, filepath.Join(cwd, "tinytap.toml"), "")
	write(t, filepath.Join(xdg, "tinytap", "config.toml"), "")

	got := find(cwd, xdg, "")
	want := filepath.Join(cwd, "tinytap.toml")
	if got != want {
		t.Errorf("find() = %q, want %q (cwd should win)", got, want)
	}
}

func TestFind_NoneFound(t *testing.T) {
	cwd := t.TempDir()
	xdg := t.TempDir()

	if got := find(cwd, xdg, ""); got != "" {
		t.Errorf("find() = %q, want empty", got)
	}
}

// --- Load ---

func TestLoad_NoFileFound_ReturnsDefaults(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output != "auto" {
		t.Errorf("Output = %q, want auto", cfg.Output)
	}
	if cfg.Verbose {
		t.Error("Verbose = true, want false")
	}
}

func TestLoad_CwdFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	write(t, filepath.Join(dir, "tinytap.toml"), "output = \"stdout\"\nverbose = true\n")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output != "stdout" {
		t.Errorf("Output = %q, want stdout", cfg.Output)
	}
	if !cfg.Verbose {
		t.Error("Verbose = false, want true")
	}
}

func TestLoad_FilterSection(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	write(t, filepath.Join(dir, "tinytap.toml"), `
output = "tui"

[filter]
pid = [123, 456]
comm = ["nginx", "curl"]
`)

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	wantPID := []uint32{123, 456}
	if len(cfg.Filter.PID) != len(wantPID) || cfg.Filter.PID[0] != wantPID[0] || cfg.Filter.PID[1] != wantPID[1] {
		t.Errorf("Filter.PID = %v, want %v", cfg.Filter.PID, wantPID)
	}
	wantComm := []string{"nginx", "curl"}
	if len(cfg.Filter.Comm) != len(wantComm) || cfg.Filter.Comm[0] != wantComm[0] || cfg.Filter.Comm[1] != wantComm[1] {
		t.Errorf("Filter.Comm = %v, want %v", cfg.Filter.Comm, wantComm)
	}
}

func TestLoad_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.toml")
	write(t, custom, "output = \"tui\"\n")

	cfg, err := Load(custom)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output != "tui" {
		t.Errorf("Output = %q, want tui", cfg.Output)
	}
}

func TestLoad_ExplicitPathMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err == nil {
		t.Error("want error for missing --config path")
	}
}

func TestLoad_InvalidOutput(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "bad.toml")
	write(t, custom, "output = \"invalid\"\n")

	_, err := Load(custom)
	if err == nil {
		t.Error("want error for invalid output value")
	}
}

func TestLoad_MalformedTOML(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "malformed.toml")
	write(t, custom, "this is not valid toml {{{")

	_, err := Load(custom)
	if err == nil {
		t.Error("want error for malformed TOML")
	}
}

func TestLoad_GetwdError(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(""); err == nil {
		t.Error("want error when the cwd no longer exists")
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
