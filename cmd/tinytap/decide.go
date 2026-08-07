package main

import (
	"fmt"
	"os"
)

// The TUI assumes a terminal at least this large; below it the layout breaks,
// so both auto and an explicit config output="tui" decline to start (see #32).
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

// stdoutHint points users at the config file's output="stdout" setting —
// --output/--verbose were retired as CLI flags in #217, replaced by the TOML
// config (see Config).
const stdoutHint = `run "tinytap config init" and set output = "stdout" in the resulting config file`

// decideOutput picks the output backend. The TUI is the default; the raw
// stdout line stream is opt-in via the config file's output="stdout" only.
// So auto and tui never silently stream — when the terminal can't host the
// TUI they print guidance and bail (outputExit), pointing at the config
// file's stdout mode for piping or logging. It returns the terminal size to
// seed the TUI's first frame.
//
// isTerminal and getSize are injected so the function is testable without a
// real TTY; callers pass term.IsTerminal and term.GetSize.
func decideOutput(mode string, isTerminal func(int) bool, getSize func(int) (int, int, error)) (choice outputChoice, width, height int) {
	if mode == "stdout" {
		return outputStdout, 0, 0
	}
	// Both streams must be terminals: stdout to render the alt-screen, stdin
	// to receive keystrokes (q / Ctrl-C). A piped stdin would draw a TUI that
	// can never be quit; a piped stdout has nowhere to render.
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
	// The minimum size is a hard floor for the TUI: below it the layout
	// breaks (visibleRows can hit 0, the panel can't keep a row navigable),
	// so both auto and an explicit config output="tui" bail rather than
	// render a broken frame. output="stdout" is the escape hatch for any size.
	if w < minCols || h < minRows {
		fmt.Fprintf(os.Stderr, "Terminal too small for the TUI — need at least %dx%d, got %dx%d.\n", minCols, minRows, w, h)
		fmt.Fprintln(os.Stderr, "Resize the terminal and retry, or "+stdoutHint+".")
		return outputExit, 0, 0
	}
	return outputTUI, w, h
}
