// Package tui renders the capture pipeline as a live Bubble Tea table: one
// row per paired HTTP exchange, scrolling in as exchanges are captured. It
// is the default output for an interactive terminal; cmd/tinytap falls back
// to internal/output/stdout when stdout isn't a TTY or is too small.
//
// This is the v0.2.0 TUI: a live table with vim-style navigation (#38, #39) —
// a ▸ marker, ↑↓/jk/g/G movement, and auto-scroll follow that pauses while the
// user inspects and re-arms at the newest row — plus a toggleable detail panel
// (#40, Enter to open / Enter or Esc to close) whose body is still a
// placeholder until structured headers (#34) and the decoded/hex body (#35)
// land. OnEvent and OnMessage stay no-ops — the TUI cares only about completed
// exchanges (OnPaired).
package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// Sink owns the Bubble Tea program and feeds it rows. The capture loop runs
// on its own goroutine and calls OnPaired; Run drives the UI on the main
// goroutine. Program.Send is goroutine-safe, so no extra channel is needed
// between the two.
type Sink struct {
	prog   *tea.Program
	anchor http.TimeAnchor
}

// New builds the program sized to the terminal already measured by the
// caller (so the first frame is laid out correctly before Bubble Tea's own
// WindowSizeMsg arrives). It does not start the UI — call Run for that.
func New(width, height int) *Sink {
	s := &Sink{}
	s.prog = tea.NewProgram(newModel(width, height), tea.WithAltScreen())
	return s
}

// OnEvent and OnMessage are no-ops: the table is built from paired
// exchanges, not raw syscalls or half-open messages.
func (s *Sink) OnEvent(*events.Event)  {}
func (s *Sink) OnMessage(http.Message) {}

// OnPaired posts a new table row to the UI. Called from the capture
// goroutine; the time anchor is stamped here (single-threaded with respect
// to the capture loop) so the model stays free of timing logic.
func (s *Sink) OnPaired(pe http.PairedEvent) {
	s.prog.Send(rowMsg(newRow(pe, s.anchor.WallTime(pe.ReqTsNs))))
}

// Run starts the UI and blocks until the user quits (q / Ctrl-C) or Quit is
// called from the capture side.
func (s *Sink) Run() error {
	_, err := s.prog.Run()
	return err
}

// Quit asks the UI to exit. Safe to call after the program has already
// stopped (the capture-died path), where it is a no-op.
func (s *Sink) Quit() { s.prog.Quit() }

// Close releases sink resources; the program is torn down by Run returning,
// so there is nothing extra to do here.
func (s *Sink) Close() error { return nil }
