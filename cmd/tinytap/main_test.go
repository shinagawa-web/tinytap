package main

import (
	"errors"
	"testing"
)

func TestMain_Success(t *testing.T) {
	oldExit := osExit
	osExit = func(code int) { t.Errorf("unexpected osExit(%d)", code) }
	defer func() { osExit = oldExit }()

	oldRunner := runner
	runner = func() error { return nil }
	defer func() { runner = oldRunner }()

	main()
}

func TestMain_ErrorCallsOsExit(t *testing.T) {
	exitCode := -1
	oldExit := osExit
	osExit = func(code int) { exitCode = code }
	defer func() { osExit = oldExit }()

	oldRunner := runner
	runner = func() error { return errors.New("boom") }
	defer func() { runner = oldRunner }()

	main()
	if exitCode != 1 {
		t.Errorf("want exit 1, got %d", exitCode)
	}
}

func TestMain_SilentExitNoMessage(t *testing.T) {
	exitCode := -1
	oldExit := osExit
	osExit = func(code int) { exitCode = code }
	defer func() { osExit = oldExit }()

	oldRunner := runner
	runner = func() error { return errSilentExit }
	defer func() { runner = oldRunner }()

	main()
	if exitCode != 1 {
		t.Errorf("want exit 1, got %d", exitCode)
	}
}
