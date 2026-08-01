package doctor

import (
	"errors"
	"testing"
)

func TestCheckDryRunLoad_RemoveMemlockError(t *testing.T) {
	old := removeMemlock
	removeMemlock = func() error { return errors.New("boom") }
	defer func() { removeMemlock = old }()

	c := checkDryRunLoad()
	if c.Severity != Blocking {
		t.Errorf("Severity = %v, want Blocking", c.Severity)
	}
	if c.Fix == "" || c.Affects == "" {
		t.Error("want Affects and Fix set")
	}
}

func TestCheckDryRunLoad_LoadError(t *testing.T) {
	oldRemove := removeMemlock
	removeMemlock = func() error { return nil }
	defer func() { removeMemlock = oldRemove }()

	oldLoad := loadTinytapObjects
	loadTinytapObjects = func() error { return errors.New("verifier rejected program") }
	defer func() { loadTinytapObjects = oldLoad }()

	c := checkDryRunLoad()
	if c.Severity != Blocking {
		t.Errorf("Severity = %v, want Blocking", c.Severity)
	}
	if c.Detail != "verifier rejected program" {
		t.Errorf("Detail = %q", c.Detail)
	}
}

func TestCheckDryRunLoad_Success(t *testing.T) {
	oldRemove := removeMemlock
	removeMemlock = func() error { return nil }
	defer func() { removeMemlock = oldRemove }()

	oldLoad := loadTinytapObjects
	loadTinytapObjects = func() error { return nil }
	defer func() { loadTinytapObjects = oldLoad }()

	c := checkDryRunLoad()
	if c.Severity != OK {
		t.Errorf("Severity = %v, want OK", c.Severity)
	}
}
