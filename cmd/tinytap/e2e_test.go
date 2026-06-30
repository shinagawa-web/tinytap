//go:build privileged

package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
	"github.com/shinagawa-web/tinytap/internal/output"
	httpproto "github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// collectSink gathers PairedEvents into a buffered channel for assertion.
type collectSink struct {
	ch chan httpproto.PairedEvent
}

func newCollectSink() *collectSink {
	return &collectSink{ch: make(chan httpproto.PairedEvent, 128)}
}

func (s *collectSink) OnEvent(*events.Event)               {}
func (s *collectSink) OnMessage(httpproto.Message)         {}
func (s *collectSink) OnPaired(pe httpproto.PairedEvent)   { s.ch <- pe }
func (s *collectSink) Close() error                        { return nil }

var _ output.Sink = (*collectSink)(nil)

// waitFor drains ch until pred returns true or timeout elapses.
func waitFor(t *testing.T, ch <-chan httpproto.PairedEvent, timeout time.Duration, pred func(httpproto.PairedEvent) bool) httpproto.PairedEvent {
	t.Helper()
	dl := time.After(timeout)
	for {
		select {
		case pe := <-ch:
			if pred(pe) {
				return pe
			}
		case <-dl:
			t.Fatal("timed out waiting for PairedEvent")
			return httpproto.PairedEvent{}
		}
	}
}

// TestE2ECapturePipeline wires the real BPF probes to the full capture
// pipeline and asserts on the PairedEvents each HTTP scenario produces.
//
// ownPid=0: the BPF check is `if (pid == own_pid) return`, so only PID 0
// (the kernel swapper) is skipped.  Our test process is never PID 0, so its
// socket syscalls pass through and get captured.
func TestE2ECapturePipeline(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root / CAP_BPF")
	}

	tt, err := loader.Load(0)
	if err != nil {
		t.Fatalf("loader.Load: %v", err)
	}
	t.Cleanup(func() { _ = tt.Close() })

	sink := newCollectSink()
	// sweepInterval=100ms, pendingTimeout=400ms: the abandoned sub-test relies
	// on the sweeper; the other sub-tests complete long before 400ms.
	go captureWithOptions(tt.Reader, sink, 100*time.Millisecond, 400*time.Millisecond)

	t.Run("GET", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/e2e-get")
		if err != nil {
			t.Fatalf("http.Get: %v", err)
		}
		_ = resp.Body.Close()

		pe := waitFor(t, sink.ch, 5*time.Second, func(pe httpproto.PairedEvent) bool {
			return !pe.Abandoned && pe.Method == "GET" && pe.Path == "/e2e-get" && pe.Status == 200
		})
		if pe.Pid != uint32(os.Getpid()) {
			t.Errorf("Pid = %d, want %d", pe.Pid, os.Getpid())
		}
		if pe.Comm == "" {
			t.Error("Comm must not be empty")
		}
	})

	t.Run("POST", func(t *testing.T) {
		const body = "tinytap-post-body"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusCreated)
		}))
		defer srv.Close()

		resp, err := http.Post(srv.URL+"/e2e-post", "text/plain", strings.NewReader(body))
		if err != nil {
			t.Fatalf("http.Post: %v", err)
		}
		_ = resp.Body.Close()

		pe := waitFor(t, sink.ch, 5*time.Second, func(pe httpproto.PairedEvent) bool {
			return !pe.Abandoned && pe.Method == "POST" && pe.Path == "/e2e-post" && pe.Status == 201
		})
		if pe.ReqBytes != len(body) {
			t.Errorf("ReqBytes = %d, want %d", pe.ReqBytes, len(body))
		}
	})

	t.Run("chunked", func(t *testing.T) {
		const chunkBody = "tinytap-chunk-data"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Omitting Content-Length causes net/http to use chunked transfer encoding.
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(chunkBody)) //nolint:errcheck
			w.(http.Flusher).Flush()
		}))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/e2e-chunked")
		if err != nil {
			t.Fatalf("http.Get: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		pe := waitFor(t, sink.ch, 5*time.Second, func(pe httpproto.PairedEvent) bool {
			return !pe.Abandoned && pe.Method == "GET" && pe.Path == "/e2e-chunked" && pe.Status == 200
		})
		if pe.ResBytes == 0 {
			t.Error("chunked ResBytes = 0, want > 0")
		}
	})

	t.Run("abandoned", func(t *testing.T) {
		// A server that accepts the connection and absorbs the request but never
		// sends a response, simulating a hung backend.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.ReadAll(conn)
			_ = conn.Close()
		}()

		// The client blocks waiting for a response that never arrives.  A
		// 2-second timeout lets the goroutine exit cleanly after the sweeper
		// has already evicted the request (pendingTimeout=400ms).
		client := &http.Client{
			Transport: &http.Transport{DisableKeepAlives: true},
			Timeout:   2 * time.Second,
		}
		go func() {
			resp, err := client.Get("http://" + ln.Addr().String() + "/e2e-abandoned")
			if err == nil {
				_ = resp.Body.Close()
			}
		}()

		// Sweeper evicts the pending request after pendingTimeout (400ms).
		pe := waitFor(t, sink.ch, 5*time.Second, func(pe httpproto.PairedEvent) bool {
			return pe.Abandoned && pe.Path == "/e2e-abandoned"
		})
		if pe.AbandonReason != httpproto.AbandonReasonTimeout {
			t.Errorf("AbandonReason = %q, want %q", pe.AbandonReason, httpproto.AbandonReasonTimeout)
		}
	})
}
