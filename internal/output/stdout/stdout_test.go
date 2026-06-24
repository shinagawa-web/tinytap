package stdout

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

func TestNewDefaultsToStdout(t *testing.T) {
	s := New(false)
	if s.w != os.Stdout {
		t.Error("New should write to os.Stdout by default")
	}
	if s.verbose {
		t.Error("New(false) should set verbose=false")
	}
	s2 := New(true)
	if !s2.verbose {
		t.Error("New(true) should set verbose=true")
	}
}

func TestOnEventNoOp(t *testing.T) {
	s := &Sink{w: &bytes.Buffer{}}
	s.OnEvent(&events.Event{}) // must not panic
}

func TestOnMessageNoOp(t *testing.T) {
	s := &Sink{w: &bytes.Buffer{}}
	s.OnMessage(http.Message{}) // must not panic
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

func TestOnPairedNonVerbose(t *testing.T) {
	var buf bytes.Buffer
	s := &Sink{w: &buf}
	pe := pairedEvent()
	s.OnPaired(pe)
	out := buf.String()

	for _, want := range []string{"GET", "/api", "200"} {
		if !strings.Contains(out, want) {
			t.Errorf("non-verbose output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "    > ") || strings.Contains(out, "    < ") {
		t.Errorf("non-verbose output should not contain detail lines:\n%s", out)
	}
}

func TestOnPairedVerbose(t *testing.T) {
	var buf bytes.Buffer
	s := &Sink{w: &buf, verbose: true}
	pe := pairedEvent()
	s.OnPaired(pe)
	out := buf.String()

	for _, want := range []string{"GET", "/api", "200"} {
		if !strings.Contains(out, want) {
			t.Errorf("verbose output missing %q:\n%s", want, out)
		}
	}
	for _, want := range http.RenderPairedDetail(pe) {
		if !strings.Contains(out, want) {
			t.Errorf("verbose output missing detail line %q:\n%s", want, out)
		}
	}
}

func TestCloseReturnsNil(t *testing.T) {
	if err := New(false).Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}
