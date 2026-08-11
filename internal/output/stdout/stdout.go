package stdout

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

var encodeJSONL = http.EncodeJSONL

type Sink struct {
	w io.Writer
}

func New() *Sink {
	return &Sink{w: os.Stdout}
}

func (s *Sink) OnEvent(_ *events.Event) {}

func (s *Sink) OnMessage(_ http.Message) {}

func (s *Sink) OnPaired(pe http.PairedEvent) {
	b, err := encodeJSONL(pe)
	if err != nil {
		log.Printf("tinytap: encode jsonl: %v", err)
		return
	}
	_, _ = fmt.Fprintln(s.w, string(b))
}

func (s *Sink) Close() error { return nil }
