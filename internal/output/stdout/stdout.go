// Package stdout renders the capture pipeline's output as the line-based
// format tinytap shipped in v0.1.0: one raw line per BPF event, one line
// per completed HTTP message, and one demo line per paired request/response.
//
// It is the fallback sink — selected by --no-tui, and (once the TUI lands)
// by a non-terminal stdout or a terminal too small for the table.
// scripts/demo.sh and `make run-raw` depend on this exact output.
package stdout

import (
	"bytes"
	"fmt"
	"log"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// Sink writes v0.1.0-format lines via the standard logger. It holds the
// time anchor used to stamp paired demo lines with wall-clock time.
type Sink struct {
	anchor http.TimeAnchor
}

// New returns a stdout sink ready to consume the capture pipeline.
func New() *Sink {
	return &Sink{}
}

// OnEvent prints the raw per-syscall line: syscall name, pid/tid/fd, byte
// count, comm, and — when a payload sample is present — its printable form.
func (s *Sink) OnEvent(e *events.Event) {
	name := events.SyscallNames[e.Syscall]
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	line := fmt.Sprintf("%-8s pid=%-6d tid=%-6d fd=%-3d bytes=%-6d comm=%s",
		name, e.Pid, e.Tid, e.Fd, e.Bytes, comm)
	if e.PayloadLen > 0 {
		n := int(e.PayloadLen)
		if n > len(e.Payload) {
			n = len(e.Payload)
		}
		line += " | " + renderPayload(e.Payload[:n])
	}
	log.Println(line)
}

// OnMessage prints the per-message debug line (request or response summary).
func (s *Sink) OnMessage(m http.Message) {
	log.Println(http.RenderMessage(m))
}

// OnPaired prints the demo line for a matched request/response exchange.
func (s *Sink) OnPaired(pe http.PairedEvent) {
	log.Println(http.RenderPaired(pe, s.anchor.WallTime(pe.ReqTsNs)))
}

// Close is a no-op; the stdout sink holds no resources to release.
func (s *Sink) Close() error { return nil }

// renderPayload turns a raw byte slice into a single-line printable string.
// Printable ASCII (0x20–0x7E) is kept as-is; CR/LF/TAB are escaped so the
// log stays on one line; everything else becomes `.`.
func renderPayload(p []byte) string {
	out := make([]byte, 0, len(p)+8)
	for _, b := range p {
		switch {
		case b == '\r':
			out = append(out, '\\', 'r')
		case b == '\n':
			out = append(out, '\\', 'n')
		case b == '\t':
			out = append(out, '\\', 't')
		case b >= 0x20 && b <= 0x7e:
			out = append(out, b)
		default:
			out = append(out, '.')
		}
	}
	return string(out)
}
