package stdout

import (
	"fmt"
	"io"
	"os"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

type Sink struct {
	w       io.Writer
	verbose bool
	anchor  http.TimeAnchor
}

func New(verbose bool) *Sink {
	return &Sink{w: os.Stdout, verbose: verbose, anchor: http.NewTimeAnchor()}
}

func (s *Sink) OnEvent(_ *events.Event) {}

func (s *Sink) OnMessage(_ http.Message) {}

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

func (s *Sink) Close() error { return nil }
