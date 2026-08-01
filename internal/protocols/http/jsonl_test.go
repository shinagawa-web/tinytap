package http

import (
	"bytes"
	"encoding/json"
	"reflect"
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

	// resBodyTruncated is exactly the field RenderPaired's summary line
	// never shows (#190) — proving it survives here is the point of adding
	// a full-fidelity encoding in the first place.
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

// summaryFields are read (directly or via the caller-supplied `when` derived
// from ReqTsNs) by RenderPaired/RenderAbandoned, tinytap's one-line stdout
// summary — either unconditionally or depending on the exchange kind (e.g.
// Status only for a completed pair). Abandoned itself selects which of the
// two renderers runs, so it counts as reaching the output too.
var summaryFields = map[string]bool{
	"ReqTsNs": true, "Latency": true, "Pid": true, "Comm": true,
	"Method": true, "Path": true, "Status": true, "ResBytes": true,
	"Abandoned": true, "AbandonReason": true, "SSLFallback": true,
}

// detailFields are read only by RenderPairedDetail, the -v continuation
// lines. Method and Path are already in summaryFields.
var detailFields = map[string]bool{
	"ReqVersion": true, "Reason": true, "ResVersion": true,
	"ReqHeaders": true, "ResHeaders": true,
}

// jsonlOnlyFields are captured on PairedEvent but never rendered as text
// today — reachable only through EncodeJSONL. ReqBodyTruncated and
// ResBodyTruncated landing here (rather than in summaryFields) is exactly
// the gap #190 tracks; move them to summaryFields once that's fixed.
var jsonlOnlyFields = map[string]bool{
	"Fd": true, "ReqBytes": true, "ReqBody": true,
	"ReqBodyTruncated": true, "ResBody": true, "ResBodyTruncated": true,
	"SSL": true,
}

// TestPairedEventFieldsAreClassified is the drift guard #192 exists to add.
// Every field on PairedEvent must be accounted for in at least one of the
// three sets above. Add a field to PairedEvent without updating one of
// them, and this test fails — the silent gap that let ReqBodyTruncated/
// ResBodyTruncated exist on the struct without ever reaching
// RenderPaired/RenderAbandoned (#190) can't happen again unnoticed, even
// though EncodeJSONL itself can never drop a field (it's a plain
// encoding/json reflection over the whole struct).
func TestPairedEventFieldsAreClassified(t *testing.T) {
	typ := reflect.TypeOf(PairedEvent{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !summaryFields[name] && !detailFields[name] && !jsonlOnlyFields[name] {
			t.Errorf("PairedEvent.%s is not classified in summaryFields, detailFields, or jsonlOnlyFields in jsonl_test.go — decide whether/where it should render and update the appropriate set", name)
		}
	}
}
