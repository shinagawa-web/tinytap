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
// Implementations decide how to render — and both current sinks render only
// OnPaired. stdout prints it as a summary line (with -v hanging the headers
// beneath) and no-ops OnEvent/OnMessage; the TUI draws it as a table row and
// likewise no-ops the other two. The raw OnEvent / per-message OnMessage
// callbacks stay on the interface for future sinks that may want them. Close
// releases any resources the sink holds.
type Sink interface {
	OnEvent(e *events.Event)
	OnMessage(m http.Message)
	OnPaired(pe http.PairedEvent)
	Close() error
}
