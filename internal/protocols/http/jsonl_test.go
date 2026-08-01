package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
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

// TestRoundTripJSONLPreservesAllFields is what makes routing render.go's
// formatters through roundTripJSONL (PairedEvent -> JSONL -> text, #192)
// safe rather than a silent, lossy detour: every field, populated with a
// distinct non-zero value, must survive the encode/decode trip unchanged.
func TestRoundTripJSONLPreservesAllFields(t *testing.T) {
	pe := PairedEvent{
		ReqTsNs: 111, Latency: 222 * time.Millisecond, Pid: 333, Fd: 444,
		Comm: "curl", Method: "GET", Path: "/x", ReqVersion: "HTTP/1.1",
		Status: 200, Reason: "OK", ResVersion: "HTTP/1.0",
		ResBytes: 555, ReqBytes: 666,
		ReqHeaders: []Header{{Name: "A", Value: "1"}},
		ResHeaders: []Header{{Name: "B", Value: "2"}},
		Abandoned:  true, AbandonReason: AbandonReasonTimeout,
		ReqBody: []byte("req"), ReqBodyTruncated: true,
		ResBody: []byte("res"), ResBodyTruncated: true,
		SSL: 777, SSLFallback: true,
	}

	got := roundTripJSONL(pe)

	if !reflect.DeepEqual(got, pe) {
		t.Errorf("roundTripJSONL lost or changed a field:\n got: %+v\nwant: %+v", got, pe)
	}
}

// TestRoundTripJSONLPanicsOnEncodeError exercises roundTripJSONL's encode
// failure branch, otherwise unreachable since PairedEvent's fields are all
// JSON-safe — it documents (and enforces via coverage) that a future field
// breaking that invariant fails loudly rather than silently.
func TestRoundTripJSONLPanicsOnEncodeError(t *testing.T) {
	orig := jsonMarshal
	defer func() { jsonMarshal = orig }()
	jsonMarshal = func(any) ([]byte, error) { return nil, errors.New("boom") }

	defer func() {
		if recover() == nil {
			t.Errorf("expected roundTripJSONL to panic on an encode error")
		}
	}()
	roundTripJSONL(PairedEvent{})
}

// TestRoundTripJSONLPanicsOnDecodeError is the decode-side counterpart to
// TestRoundTripJSONLPanicsOnEncodeError.
func TestRoundTripJSONLPanicsOnDecodeError(t *testing.T) {
	orig := jsonUnmarshal
	defer func() { jsonUnmarshal = orig }()
	jsonUnmarshal = func([]byte, any) error { return errors.New("boom") }

	defer func() {
		if recover() == nil {
			t.Errorf("expected roundTripJSONL to panic on a decode error")
		}
	}()
	roundTripJSONL(PairedEvent{})
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
