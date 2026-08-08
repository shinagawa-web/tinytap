package http

import (
	"testing"

	"github.com/shinagawa-web/tinytap/internal/events"
)

// FuzzParse feeds arbitrary byte sequences through Parser.Feed, driving the
// HTTP/1.x state machine (stateNeedStartLine through stateNeedTrailer) with
// input that need not be well-formed HTTP. parser.go parses raw bytes
// captured off the wire — untrusted input by construction — so the only
// invariant under fuzzing is "never panic," regardless of what garbage,
// truncated, or adversarially-chunked input arrives.
func FuzzParse(f *testing.F) {
	seeds := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
		[]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"),
		[]byte("HEAD /index.html HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("HTTP/1.1 100 Continue\r\n\r\n"),
		[]byte("POST /users HTTP/1.1\r\nContent-Length: 16\r\n\r\n{\"name\":\"Alice\"}"),
		[]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0xFF\r\n\r\n"),
		[]byte("HTTP/1.1\r\n\r\n"),
		[]byte("HTTP/1.1 TWO-HUNDRED OK\r\n\r\n"),
		[]byte("GET /path\r\n\r\n"),
		[]byte("GET /path GOPHER/1.0\r\n\r\n"),
		[]byte("GET /"),
		{0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF},
		{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00},
		[]byte(`{"key":"value","other":"data"}`),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Bad-Header-No-Colon\r\nX-Good: yes\r\n\r\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewParser()
		pid, fd := uint32(1), int32(1)
		for i := 0; i < len(data); i += events.MaxPayload {
			end := i + events.MaxPayload
			if end > len(data) {
				end = len(data)
			}
			chunk := data[i:end]
			_ = p.Feed(makeEvent(events.SyscallWrite, pid, fd, uint32(len(chunk)), chunk))
		}
		p.Close(pid, fd)
	})
}
