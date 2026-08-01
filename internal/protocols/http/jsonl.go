package http

import "encoding/json"

// EncodeJSONL returns p encoded as a single JSON object — the full-fidelity,
// canonical representation of a paired exchange (#192). It's the one code
// path that can turn a PairedEvent into output without silently dropping a
// field: every field reaches this encoding automatically via encoding/json's
// reflection over the struct, with no per-field transcription to keep in
// sync. That's unlike RenderPaired/RenderAbandoned's curated one-line
// summary, which deliberately shows only a subset — kept honest about that
// subset by TestPairedEventFieldsAreClassified in jsonl_test.go rather than
// by hand-verifying it stays in sync with PairedEvent.
//
// Returns one JSON value with no trailing newline; write consecutive values
// newline-separated to produce JSON Lines (JSONL) output.
func EncodeJSONL(p PairedEvent) ([]byte, error) {
	return json.Marshal(p)
}
