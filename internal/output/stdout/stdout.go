// Package stdout renders the capture pipeline's output as a line-oriented
// HTTP exchange log (#63): one self-contained summary line per paired
// request/response, written to stdout. With verbose mode it hangs the
// request/response start lines and headers under each summary.
//
// The raw per-syscall events (OnEvent) and the per-message request/response
// lines (OnMessage) are intentionally dropped here — the paired line already
// carries method/path/status, and the raw syscalls were pure noise. Data goes
// to stdout; operational logs (startup, errors) stay on the global logger's
// stderr, so a consumer can `> log` the data without the diagnostics.
//
// It is selected only by an explicit --output stdout: when the terminal
// can't host the TUI, auto/tui print guidance and exit rather than falling
// back here (see decideOutput in cmd/tinytap). scripts/demo.sh and
// `make run-raw` depend on this output.
package stdout

import (
	"fmt"
	"io"
	"os"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// Sink writes exchange lines to w (stdout by default). It holds the time
// anchor used to stamp summary lines with wall-clock time.
type Sink struct {
	w       io.Writer
	verbose bool
	anchor  http.TimeAnchor
}

// New returns a stdout sink ready to consume the capture pipeline. When
// verbose is set, each summary line is followed by its request/response
// start lines and headers.
func New(verbose bool) *Sink {
	return &Sink{w: os.Stdout, verbose: verbose}
}

// OnEvent is a no-op: stdout does not print raw per-syscall lines (#63). The
// pipeline still delivers raw events to every sink, so the method stays to
// satisfy the output.Sink interface.
func (s *Sink) OnEvent(_ *events.Event) {}

// OnMessage is a no-op: the paired summary line (OnPaired) carries the
// request/response details, so the per-message lines are redundant here.
func (s *Sink) OnMessage(_ http.Message) {}

// OnPaired prints the one-line summary for a paired exchange, or an abandoned
// line when the request never received a response.
func (s *Sink) OnPaired(pe http.PairedEvent) {
	if pe.Abandoned {
		_, _ = fmt.Fprintln(s.w, http.RenderAbandoned(pe, s.anchor.WallTime(pe.ReqTsNs)))
		return
	}
	_, _ = fmt.Fprintln(s.w, http.RenderPaired(pe, s.anchor.WallTime(pe.ReqTsNs)))
	if s.verbose {
		for _, line := range http.RenderPairedDetail(pe) {
			_, _ = fmt.Fprintln(s.w, line)
		}
	}
}

// Close is a no-op; the stdout sink holds no resources to release.
func (s *Sink) Close() error { return nil }
