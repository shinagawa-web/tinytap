package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

type Sink struct {
	prog   *tea.Program
	anchor http.TimeAnchor
}

func New(width, height int) *Sink {
	s := &Sink{anchor: http.NewTimeAnchor()}
	s.prog = tea.NewProgram(newModel(width, height), tea.WithAltScreen())
	return s
}

func (s *Sink) OnEvent(*events.Event)  {}
func (s *Sink) OnMessage(http.Message) {}

func (s *Sink) OnPaired(pe http.PairedEvent) {
	s.prog.Send(rowMsg(newRow(pe, s.anchor.WallTime(pe.ReqTsNs))))
}

func (s *Sink) Run() error {
	_, err := s.prog.Run()
	return err
}

func (s *Sink) Quit() { s.prog.Quit() }

func (s *Sink) SendDiag(line string) { s.prog.Send(diagMsg(line)) }

func (s *Sink) SendDrops(n uint64) { s.prog.Send(dropsMsg(n)) }

func (s *Sink) Close() error { return nil }
