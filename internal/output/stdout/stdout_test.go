package stdout

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

func TestNewDefaultsToStdout(t *testing.T) {
	s := New()
	if s.w != os.Stdout {
		t.Error("New should write to os.Stdout by default")
	}
}

func TestOnEventNoOp(t *testing.T) {
	s := &Sink{w: &bytes.Buffer{}}
	s.OnEvent(&events.Event{})
}

func TestOnMessageNoOp(t *testing.T) {
	s := &Sink{w: &bytes.Buffer{}}
	s.OnMessage(http.Message{})
}

func pairedEvent() http.PairedEvent {
	return http.PairedEvent{
		Pid: 1234, Comm: "curl",
		Method: "GET", Path: "/api",
		Status: 200, ResBytes: 128,
		Latency:    5 * time.Millisecond,
		ReqVersion: "HTTP/1.1", ResVersion: "HTTP/1.1", Reason: "OK",
		ReqHeaders: []http.Header{{Name: "Host", Value: "localhost"}},
		ResHeaders: []http.Header{{Name: "Content-Type", Value: "text/html"}},
	}
}

func TestOnPairedWritesOneJSONLine(t *testing.T) {
	var buf bytes.Buffer
	s := &Sink{w: &buf}
	s.OnPaired(pairedEvent())
	out := buf.String()

	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output must end with a newline: %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("output must be exactly one line: %q", out)
	}

	var decoded http.PairedEvent
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Method != "GET" || decoded.Path != "/api" || decoded.Status != 200 {
		t.Errorf("decoded event missing expected fields: %+v", decoded)
	}
}

func TestOnPairedAbandoned(t *testing.T) {
	var buf bytes.Buffer
	s := &Sink{w: &buf}
	pe := http.PairedEvent{
		Pid: 5, Comm: "curl",
		Method: "GET", Path: "/slow",
		Latency:       10 * time.Millisecond,
		Abandoned:     true,
		AbandonReason: http.AbandonReasonClosed,
	}
	s.OnPaired(pe)

	var decoded http.PairedEvent
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if !decoded.Abandoned || decoded.AbandonReason != http.AbandonReasonClosed {
		t.Errorf("decoded event missing abandoned fields: %+v", decoded)
	}
}

func TestOnPairedEncodeError(t *testing.T) {
	orig := encodeJSONL
	defer func() { encodeJSONL = orig }()
	encodeJSONL = func(http.PairedEvent) ([]byte, error) { return nil, errors.New("boom") }

	var buf bytes.Buffer
	s := &Sink{w: &buf}
	s.OnPaired(pairedEvent())

	if buf.Len() != 0 {
		t.Errorf("OnPaired should write nothing on encode error, got %q", buf.String())
	}
}

func TestCloseReturnsNil(t *testing.T) {
	if err := New().Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}
