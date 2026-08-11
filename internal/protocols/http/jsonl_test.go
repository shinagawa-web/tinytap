package http

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEncodeJSONLRoundTrips(t *testing.T) {
	pe := PairedEvent{
		Pid: 100, Comm: "curl", Method: "GET", Path: "/", Status: 200,
		ResBytes: 4096, ResBodyTruncated: true,
	}
	b, err := EncodeJSONL(pe)
	if err != nil {
		t.Fatalf("EncodeJSONL: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if v, ok := decoded["resBodyTruncated"]; !ok || v != true {
		t.Errorf("resBodyTruncated missing or wrong in JSONL output: %v", decoded)
	}
	if v, ok := decoded["method"]; !ok || v != "GET" {
		t.Errorf("method missing or wrong in JSONL output: %v", decoded)
	}
}

func TestEncodeJSONLNoTrailingNewline(t *testing.T) {
	b, err := EncodeJSONL(PairedEvent{Pid: 1})
	if err != nil {
		t.Fatalf("EncodeJSONL: %v", err)
	}
	if bytes.ContainsRune(b, '\n') {
		t.Errorf("EncodeJSONL must not embed a newline — callers join lines to build JSONL: %q", b)
	}
}
