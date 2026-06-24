package main

import (
	"errors"
	"testing"
)

func TestDecideOutput_Stdout(t *testing.T) {
	choice, w, h := decideOutput("stdout", nil, nil)
	if choice != outputStdout || w != 0 || h != 0 {
		t.Errorf("want outputStdout 0x0, got %v %dx%d", choice, w, h)
	}
}

func TestDecideOutput_NotTerminal(t *testing.T) {
	choice, _, _ := decideOutput("auto", func(int) bool { return false }, nil)
	if choice != outputExit {
		t.Errorf("want outputExit, got %v", choice)
	}
}

func TestDecideOutput_GetSizeError(t *testing.T) {
	choice, _, _ := decideOutput("auto",
		func(int) bool { return true },
		func(int) (int, int, error) { return 0, 0, errors.New("no size") },
	)
	if choice != outputExit {
		t.Errorf("want outputExit, got %v", choice)
	}
}

func TestDecideOutput_TooSmall(t *testing.T) {
	choice, _, _ := decideOutput("auto",
		func(int) bool { return true },
		func(int) (int, int, error) { return minCols - 1, minRows, nil },
	)
	if choice != outputExit {
		t.Errorf("want outputExit, got %v", choice)
	}
}

func TestDecideOutput_TUI(t *testing.T) {
	choice, w, h := decideOutput("auto",
		func(int) bool { return true },
		func(int) (int, int, error) { return minCols + 10, minRows + 10, nil },
	)
	if choice != outputTUI || w != minCols+10 || h != minRows+10 {
		t.Errorf("want outputTUI %dx%d, got %v %dx%d", minCols+10, minRows+10, choice, w, h)
	}
}
