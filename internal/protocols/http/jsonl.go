package http

import (
	"encoding/json"
	"fmt"
)

var (
	jsonMarshal   = json.Marshal
	jsonUnmarshal = json.Unmarshal
)

func EncodeJSONL(p PairedEvent) ([]byte, error) {
	return jsonMarshal(p)
}

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
