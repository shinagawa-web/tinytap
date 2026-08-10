package http

import (
	"encoding/json"
	"fmt"
)

// jsonMarshal/jsonUnmarshal are var-indirected (mirroring the loaderLoad/
// attachSSLReadWrite pattern elsewhere in this codebase) purely so
// jsonl_test.go can force EncodeJSONL/roundTripJSONL's otherwise
// impossible-to-reach error branches and exercise them, rather than
// leaving them uncovered.
var (
	jsonMarshal   = json.Marshal
	jsonUnmarshal = json.Unmarshal
)

// EncodeJSONL returns p encoded as a single JSON object — the full-fidelity,
// canonical representation of a paired exchange (#192). It's the one code
// path that can turn a PairedEvent into output without silently dropping a
// field: every field reaches this encoding automatically via encoding/json's
// reflection over the struct, with no per-field transcription to keep in
// sync.
//
// Returns one JSON value with no trailing newline; write consecutive values
// newline-separated to produce JSON Lines (JSONL) output.
func EncodeJSONL(p PairedEvent) ([]byte, error) {
	return jsonMarshal(p)
}

// roundTripJSONL encodes p to JSONL and decodes it straight back into a
// PairedEvent. render.go's text renderers call this before formatting, so
// the pipeline is genuinely PairedEvent -> JSONL -> text, not two
// independent readers of the same struct: a field can only reach the
// human-readable line by first surviving the JSONL encoding. Combined with
// TestPairedEventFieldsAreClassified (jsonl_test.go), which forces every
// PairedEvent field to be consciously placed in or kept out of the summary
// line, this closes off silent field-by-field drift between the two
// (ReqBodyTruncated is deliberately jsonl-only; see jsonlOnlyFields).
//
// PairedEvent's fields are all JSON-safe — round-tripping cannot fail for
// the type as it stands today. A failure here would mean a future field
// broke that invariant, which is worth crashing loudly on rather than
// silently rendering a wrong or empty line.
func roundTripJSONL(p PairedEvent) PairedEvent {
	b, err := EncodeJSONL(p)
	if err != nil {
		panic(fmt.Sprintf("roundTripJSONL: encode: %v", err))
	}
	var decoded PairedEvent
	if err := jsonUnmarshal(b, &decoded); err != nil {
		panic(fmt.Sprintf("roundTripJSONL: decode: %v", err))
	}
	return decoded
}
