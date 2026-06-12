// Package output defines the seam between tinytap's capture pipeline and
// how observations are rendered. The capture loop in cmd/tinytap drives a
// Sink; it never decides whether output goes to stdout or to a TUI.
//
// This is the umbrella package for output backends (mirrors the
// internal/protocols/ shape): internal/output/stdout renders the v0.1.0
// lines, and a future internal/output/tui will render the v0.2.0 Bubble
// Tea table.
package output

import (
	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// Sink consumes the capture pipeline's output. The capture loop calls these
// in wire order for each BPF event:
//
//   - OnEvent once, with the decoded raw event;
//   - OnMessage for every HTTP message whose headers that event completed;
//   - OnPaired for every request/response pair that event completed.
//
// Implementations decide how to render. stdout prints all three as lines;
// a TUI cares only about OnPaired (one row per exchange) and no-ops the
// rest. Close releases any resources the sink holds.
type Sink interface {
	OnEvent(e *events.Event)
	OnMessage(m http.Message)
	OnPaired(pe http.PairedEvent)
	Close() error
}
