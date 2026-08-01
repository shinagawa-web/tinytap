package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- find ---

func TestFind_CwdCandidate(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "tinytap.toml"), "output = \"stdout\"\n")

	got, err := find(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "tinytap.toml")
	if got != want {
		t.Errorf("find() = %q, want %q", got, want)
	}
}

func TestFind_XDGCandidate(t *testing.T) {
	cwd := t.TempDir()
	xdg := t.TempDir()
	write(t, filepath.Join(xdg, "tinytap", "config.toml"), "output = \"stdout\"\n")

	got, err := find(cwd, xdg, "")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(xdg, "tinytap", "config.toml")
	if got != want {
		t.Errorf("find() = %q, want %q", got, want)
	}
}

func TestFind_HomeFallback(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	write(t, filepath.Join(home, ".config", "tinytap", "config.toml"), "output = \"stdout\"\n")

	got, err := find(cwd, "", home)
	if err != nil {
		t.Fatal(err)
	}
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

	got, err := find(cwd, xdg, "")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(cwd, "tinytap.toml")
	if got != want {
		t.Errorf("find() = %q, want %q (cwd should win)", got, want)
	}
}

func TestFind_NoneFound(t *testing.T) {
	cwd := t.TempDir()
	xdg := t.TempDir()

	got, err := find(cwd, xdg, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("find() = %q, want empty", got)
	}
}

func TestFind_CwdStatError(t *testing.T) {
	parent := t.TempDir()
	cwd := filepath.Join(parent, "locked")
	if err := os.Mkdir(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(cwd, "tinytap.toml"), "")
	if err := os.Chmod(cwd, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(cwd, 0o755) }() // restore so t.TempDir cleanup can remove it

	if _, err := find(cwd, "", ""); err == nil {
		t.Error("want error for a permission-denied stat, not a silent skip")
	}
}

func TestFind_XDGStatError(t *testing.T) {
	cwd := t.TempDir()
	parent := t.TempDir()
	xdg := filepath.Join(parent, "locked")
	if err := os.Mkdir(xdg, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(xdg, "tinytap", "config.toml"), "")
	if err := os.Chmod(xdg, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(xdg, 0o755) }()

	if _, err := find(cwd, xdg, ""); err == nil {
		t.Error("want error for a permission-denied stat, not a silent skip")
	}
}

// --- Load ---

func TestLoad_SearchError(t *testing.T) {
	// cwd itself must stay traversable (Chdir needs execute permission on
	// it); the permission-denied candidate is the XDG dir instead, whose
	// path find() stats without ever chdir-ing into it.
	t.Chdir(t.TempDir())
	parent := t.TempDir()
	xdg := filepath.Join(parent, "locked")
	if err := os.Mkdir(xdg, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(xdg, "tinytap", "config.toml"), "")
	if err := os.Chmod(xdg, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(xdg, 0o755) }()
	t.Setenv("XDG_CONFIG_HOME", xdg)

	if _, err := Load(""); err == nil {
		t.Error("want error propagated from find's permission-denied stat")
	}
}

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

// --- Init ---

func TestInit_WritesLoadableDefaultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tinytap.toml")

	if err := Init(path, false); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("generated file didn't load: %v", err)
	}
	if cfg.Output != "auto" {
		t.Errorf("Output = %q, want auto", cfg.Output)
	}
	if cfg.Verbose {
		t.Error("Verbose = true, want false")
	}
}

func TestInit_WrittenFileListsFilterKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tinytap.toml")

	if err := Init(path, false); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{"output = \"auto\"", "verbose = false", "[filter]", "pid = []", "comm = []"} {
		if !strings.Contains(got, want) {
			t.Errorf("Init() output = %q, want it to contain %q", got, want)
		}
	}
}

func TestInit_RefusesExistingWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tinytap.toml")
	write(t, path, "output = \"stdout\"\n")

	err := Init(path, false)
	if err == nil {
		t.Fatal("want error for an existing file without --force")
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "output = \"stdout\"\n" {
		t.Errorf("existing file was modified: %q", string(data))
	}
}

func TestInit_ForceOverwritesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tinytap.toml")
	write(t, path, "output = \"stdout\"\n")

	if err := Init(path, true); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output != "auto" {
		t.Errorf("Output = %q, want auto (overwritten with defaults)", cfg.Output)
	}
}

func TestInit_ExistsStatErrorPropagates(t *testing.T) {
	parent := t.TempDir()
	locked := filepath.Join(parent, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(locked, "tinytap.toml")
	write(t, path, "")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(locked, 0o755) }()

	if err := Init(path, false); err == nil {
		t.Error("want error for a permission-denied stat, not a silent overwrite refusal")
	}
}

func TestInit_EncodeErrorPropagates(t *testing.T) {
	old := encodeTOML
	encodeTOML = func(io.Writer, any) error { return errors.New("boom") }
	defer func() { encodeTOML = old }()

	path := filepath.Join(t.TempDir(), "tinytap.toml")
	if err := Init(path, false); err == nil {
		t.Error("want error propagated from encodeTOML")
	}
}

func TestInit_CreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dirs", "tinytap.toml")

	if err := Init(path, false); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err != nil {
		t.Fatalf("generated file didn't load: %v", err)
	}
}

func TestInit_FilterDefaultsSurviveNilNormalization(t *testing.T) {
	old := defaultConfig
	defaultConfig = func() Config {
		return Config{Output: "auto", Filter: FilterConfig{PID: []uint32{99}}}
	}
	defer func() { defaultConfig = old }()

	path := filepath.Join(t.TempDir(), "tinytap.toml")
	if err := Init(path, false); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Filter.PID) != 1 || cfg.Filter.PID[0] != 99 {
		t.Errorf("Filter.PID = %v, want [99] (a non-nil default must survive Init's nil-normalization)", cfg.Filter.PID)
	}
	if cfg.Filter.Comm == nil {
		t.Error("Filter.Comm = nil, want normalized to []string{}")
	}
}

func TestInit_MkdirAllErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	write(t, blocker, "") // a regular file, not a directory
	path := filepath.Join(blocker, "sub", "tinytap.toml")

	// force=true so the pre-check (which would itself fail to stat a path
	// under a non-directory) is skipped, isolating MkdirAll's own error.
	if err := Init(path, true); err == nil {
		t.Error("want error when the parent directory can't be created")
	}
}

func TestInit_WriteFileErrorPropagates(t *testing.T) {
	// A directory as the target path: os.WriteFile fails with EISDIR.
	path := t.TempDir()

	if err := Init(path, true); err == nil {
		t.Error("want error when the target path can't be written")
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
