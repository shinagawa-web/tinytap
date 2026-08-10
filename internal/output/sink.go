package output

import (
	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

type Sink interface {
	OnEvent(e *events.Event)
	OnMessage(m http.Message)
	OnPaired(pe http.PairedEvent)
	Close() error
}
