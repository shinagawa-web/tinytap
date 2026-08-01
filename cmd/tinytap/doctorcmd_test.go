package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/config"
	"github.com/shinagawa-web/tinytap/internal/doctor"
)

func TestRunDoctorCmd_AllOK(t *testing.T) {
	oldRun := doctorRun
	doctorRun = func() []doctor.Check { return []doctor.Check{{Name: "kernel version", Severity: doctor.OK, Detail: "6.17"}} }
	defer func() { doctorRun = oldRun }()

	stdout := captureStdout(t, func() {
		if err := runDoctorCmd(); err != nil {
			t.Fatalf("want nil error, got %v", err)
		}
	})
	if !strings.Contains(stdout, "kernel version") {
		t.Errorf("stdout = %q, want it to contain the check report", stdout)
	}
}

func TestRunDoctorCmd_Blocking(t *testing.T) {
	oldRun := doctorRun
	doctorRun = func() []doctor.Check { return []doctor.Check{{Name: "kernel version", Severity: doctor.Blocking, Detail: "too old"}} }
	defer func() { doctorRun = oldRun }()

	stdout := captureStdout(t, func() {
		err := runDoctorCmd()
		if !errors.Is(err, errSilentExit) {
			t.Errorf("want errSilentExit, got %v", err)
		}
	})
	if !strings.Contains(stdout, "kernel version") {
		t.Errorf("stdout = %q, want the report printed even though it's blocking", stdout)
	}
}

func TestRunDoctorCmd_UsesRealRenderAndVersionLine(t *testing.T) {
	oldVersion := version
	version = "v9.9.9"
	defer func() { version = oldVersion }()

	oldRun := doctorRun
	doctorRun = func() []doctor.Check { return nil }
	defer func() { doctorRun = oldRun }()

	stdout := captureStdout(t, func() {
		if err := runDoctorCmd(); err != nil {
			t.Fatalf("want nil error, got %v", err)
		}
	})
	if !strings.Contains(stdout, "v9.9.9") {
		t.Errorf("stdout = %q, want it to contain the version line", stdout)
	}
}

func TestRun_DispatchesDoctorSubcommand(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap", "doctor"}
	defer func() { os.Args = old }()

	var called bool
	oldRun := doctorRun
	doctorRun = func() []doctor.Check { called = true; return nil }
	defer func() { doctorRun = oldRun }()

	captureStdout(t, func() {
		if err := run(); err != nil {
			t.Fatalf("want nil error, got %v", err)
		}
	})
	if !called {
		t.Error("want doctorRun called")
	}
}

func TestRun_DoctorSubcommandSkipsLoadConfigAndBPF(t *testing.T) {
	old := os.Args
	os.Args = []string{"tinytap", "doctor"}
	defer func() { os.Args = old }()

	oldLoadConfig := loadConfig
	loadConfig = func(string) (config.Config, error) {
		t.Fatal("loadConfig must not be called for the doctor subcommand")
		return config.Config{}, nil
	}
	defer func() { loadConfig = oldLoadConfig }()

	oldLoad := loadBPF
	loadBPF = func(uint32) (bpfSession, error) {
		t.Fatal("loadBPF must not be called for the doctor subcommand")
		return nil, nil
	}
	defer func() { loadBPF = oldLoad }()

	oldRun := doctorRun
	doctorRun = func() []doctor.Check { return nil }
	defer func() { doctorRun = oldRun }()

	captureStdout(t, func() {
		if err := run(); err != nil {
			t.Fatalf("want nil error, got %v", err)
		}
	})
}

// --- classifyLoadError ---

func TestClassifyLoadError_UsesFirstBlockingCheck(t *testing.T) {
	old := doctorRun
	doctorRun = func() []doctor.Check {
		return []doctor.Check{
			{Name: "kernel BTF", Severity: doctor.Degraded, Detail: "not present"},
			{Name: "cap_bpf", Severity: doctor.Blocking, Detail: "missing"},
			{Name: "BPF dry-run load", Severity: doctor.Blocking, Detail: "permission denied"},
		}
	}
	defer func() { doctorRun = old }()

	err := classifyLoadError(errors.New("raw load error"))
	got := err.Error()
	if !strings.Contains(got, "cap_bpf") || !strings.Contains(got, "missing") {
		t.Errorf("err = %q, want it to name the first Blocking check (cap_bpf)", got)
	}
	if strings.Contains(got, "BPF dry-run load") {
		t.Errorf("err = %q, want only the first Blocking check, not the second", got)
	}
	if !strings.Contains(got, "raw load error") {
		t.Errorf("err = %q, want the original error wrapped", got)
	}
	if !strings.Contains(got, "tinytap doctor") {
		t.Errorf("err = %q, want a pointer to `tinytap doctor`", got)
	}
}

func TestClassifyLoadError_NoBlockingCheck_FallsBackToRawError(t *testing.T) {
	old := doctorRun
	doctorRun = func() []doctor.Check {
		return []doctor.Check{{Name: "kernel version", Severity: doctor.OK, Detail: "6.17"}}
	}
	defer func() { doctorRun = old }()

	err := classifyLoadError(errors.New("raw load error"))
	if err.Error() != "load: raw load error" {
		t.Errorf("err = %q, want the plain wrapped error", err.Error())
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
