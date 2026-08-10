package main

import (
	"fmt"
	"os"
)

const (
	minCols = 120
	minRows = 24
)

type outputChoice int

const (
	outputTUI outputChoice = iota
	outputStdout
	outputExit
)

const stdoutHint = `run "tinytap config init" and set output = "stdout" in the resulting config file`

func decideOutput(mode string, isTerminal func(int) bool, getSize func(int) (int, int, error)) (choice outputChoice, width, height int) {
	if mode == "stdout" {
		return outputStdout, 0, 0
	}
	if !isTerminal(int(os.Stdout.Fd())) || !isTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "tinytap needs an interactive terminal for the TUI.")
		fmt.Fprintln(os.Stderr, "Run it in a terminal, or "+stdoutHint+" to stream lines to a pipe or file instead.")
		return outputExit, 0, 0
	}
	w, h, err := getSize(int(os.Stdout.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not determine terminal size — "+stdoutHint+" to stream lines instead.")
		return outputExit, 0, 0
	}
	if w < minCols || h < minRows {
		fmt.Fprintf(os.Stderr, "Terminal too small for the TUI — need at least %dx%d, got %dx%d.\n", minCols, minRows, w, h)
		fmt.Fprintln(os.Stderr, "Resize the terminal and retry, or "+stdoutHint+".")
		return outputExit, 0, 0
	}
	return outputTUI, w, h
}
