package main

import (
	"errors"
	"os"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/config"
)

// --- runConfigCmd ---

func TestRunConfigCmd_UnknownSubcommand(t *testing.T) {
	if err := runConfigCmd([]string{"bogus"}); err == nil {
		t.Error("want error for unknown config subcommand")
	}
}

func TestRunConfigCmd_NoSubcommand(t *testing.T) {
	if err := runConfigCmd(nil); err == nil {
		t.Error("want error when no subcommand is given")
	}
}

func TestRunConfigCmd_DispatchesInit(t *testing.T) {
	var gotPath string
	old := configInit
	configInit = func(path string, force bool) error { gotPath = path; return nil }
	defer func() { configInit = old }()

	if err := runConfigCmd([]string{"init"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "tinytap.toml" {
		t.Errorf("path = %q, want tinytap.toml", gotPath)
	}
}

// --- runConfigInit ---

func TestRunConfigInit_DefaultPath(t *testing.T) {
	var gotPath string
	var gotForce bool
	old := configInit
	configInit = func(path string, force bool) error { gotPath, gotForce = path, force; return nil }
	defer func() { configInit = old }()

	if err := runConfigInit(nil); err != nil {
		t.Fatal(err)
	}
	if gotPath != "tinytap.toml" {
		t.Errorf("path = %q, want tinytap.toml", gotPath)
	}
	if gotForce {
		t.Error("force = true, want false")
	}
}

func TestRunConfigInit_PositionalPath(t *testing.T) {
	var gotPath string
	old := configInit
	configInit = func(path string, force bool) error { gotPath = path; return nil }
	defer func() { configInit = old }()

	if err := runConfigInit([]string{"/tmp/custom.toml"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/tmp/custom.toml" {
		t.Errorf("path = %q, want /tmp/custom.toml", gotPath)
	}
}

func TestRunConfigInit_ConfigFlag(t *testing.T) {
	var gotPath string
	old := configInit
	configInit = func(path string, force bool) error { gotPath = path; return nil }
	defer func() { configInit = old }()

	if err := runConfigInit([]string{"--config", "/tmp/via-flag.toml"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/tmp/via-flag.toml" {
		t.Errorf("path = %q, want /tmp/via-flag.toml", gotPath)
	}
}

func TestRunConfigInit_PositionalWinsOverConfigFlag(t *testing.T) {
	var gotPath string
	old := configInit
	configInit = func(path string, force bool) error { gotPath = path; return nil }
	defer func() { configInit = old }()

	if err := runConfigInit([]string{"--config", "/tmp/via-flag.toml", "/tmp/positional.toml"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/tmp/positional.toml" {
		t.Errorf("path = %q, want /tmp/positional.toml (positional should win)", gotPath)
	}
}

func TestRunConfigInit_Force(t *testing.T) {
	var gotForce bool
	old := configInit
	configInit = func(path string, force bool) error { gotForce = force; return nil }
	defer func() { configInit = old }()

	if err := runConfigInit([]string{"--force"}); err != nil {
		t.Fatal(err)
	}
	if !gotForce {
		t.Error("force = false, want true")
	}
}

func TestRunConfigInit_UnknownFlag(t *testing.T) {
	if err := runConfigInit([]string{"--nonexistent"}); err == nil {
		t.Error("want error for unknown flag")
	}
}

func TestRunConfigInit_PropagatesError(t *testing.T) {
	old := configInit
	configInit = func(string, bool) error { return errors.New("boom") }
	defer func() { configInit = old }()

	if err := runConfigInit(nil); err == nil {
		t.Error("want error propagated from configInit")
	}
}

// --- run() dispatch ---

func TestRun_DispatchesConfigSubcommand(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap", "config", "init"}
	defer func() { os.Args = old }()

	var called bool
	oldInit := configInit
	configInit = func(string, bool) error { called = true; return nil }
	defer func() { configInit = oldInit }()

	if err := run(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("want configInit called")
	}
}

func TestRun_ConfigSubcommandSkipsLoadConfigAndBPF(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap", "config", "init"}
	defer func() { os.Args = old }()

	oldLoadConfig := loadConfig
	loadConfig = func(string) (config.Config, error) {
		t.Fatal("loadConfig must not be called for the config subcommand")
		return config.Config{}, nil
	}
	defer func() { loadConfig = oldLoadConfig }()

	oldLoad := loadBPF
	loadBPF = func(uint32) (bpfSession, error) {
		t.Fatal("loadBPF must not be called for the config subcommand")
		return nil, nil
	}
	defer func() { loadBPF = oldLoad }()

	oldInit := configInit
	configInit = func(string, bool) error { return nil }
	defer func() { configInit = oldInit }()

	if err := run(); err != nil {
		t.Fatal(err)
	}
}
