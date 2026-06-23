package tui

import (
	"io"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// testSink builds a Sink that reads from r and discards all output, so it
// runs cleanly in a test environment without a real terminal.
func testSink(r io.Reader) *Sink {
	s := &Sink{}
	s.prog = tea.NewProgram(
		newModel(80, 24),
		tea.WithInput(r),
		tea.WithOutput(io.Discard),
	)
	return s
}

// New must return a non-nil Sink.
func TestSinkNew(t *testing.T) {
	if s := New(80, 24); s == nil {
		t.Fatal("New returned nil")
	}
}

// OnEvent and OnMessage are intentional no-ops; they must not panic.
func TestSinkNoOps(t *testing.T) {
	s := testSink(strings.NewReader(""))
	s.OnEvent(nil)
	s.OnMessage(http.Message{})
}

// Close always returns nil.
func TestSinkClose(t *testing.T) {
	if err := testSink(strings.NewReader("")).Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

// Quit sends a stop signal; Run exits once the signal is processed.
func TestSinkRunAndQuit(t *testing.T) {
	s := testSink(strings.NewReader(""))
	done := make(chan error, 1)
	go func() { done <- s.Run() }()
	s.Quit()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after Quit")
	}
}

// OnPaired posts a rowMsg to the running program without panicking.
func TestSinkOnPaired(t *testing.T) {
	s := testSink(strings.NewReader(""))
	done := make(chan error, 1)
	go func() { done <- s.Run() }()
	s.OnPaired(http.PairedEvent{})
	s.Quit()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after OnPaired+Quit")
	}
}
