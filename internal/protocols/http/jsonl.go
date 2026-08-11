package http

import "encoding/json"

var jsonMarshal = json.Marshal

func EncodeJSONL(p PairedEvent) ([]byte, error) {
	return jsonMarshal(p)
}
