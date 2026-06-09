// Command tinytap attaches the BPF program, drains its ringbuf, parses
// the per-syscall events into HTTP messages, pairs requests with
// responses, and prints both raw and demo lines to stdout.
//
// Everything beyond this file is in internal/: the BPF lifecycle in
// internal/loader, the event struct + decode in internal/events, and
// per-protocol parsing under internal/protocols/.
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

func main() {
	tt, err := loader.Load(uint32(os.Getpid()))
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer func() {
		if err := tt.Close(); err != nil {
			log.Printf("teardown: %v", err)
		}
	}()

	log.Println("tinytap running — watching accept4/read/write/close/recvfrom/sendto/recvmsg/sendmsg. Press Ctrl-C to stop.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		tt.Reader.Close()
	}()

	parser := http.NewParser()
	pairer := http.NewPairer()
	var anchor http.TimeAnchor

	var e events.Event
	for {
		rec, err := tt.Reader.Read()
		if err != nil {
			break
		}
		if err := events.Decode(rec.RawSample, &e); err != nil {
			log.Printf("parse event: %v", err)
			continue
		}
		name := events.SyscallNames[e.Syscall]
		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		line := fmt.Sprintf("%-8s pid=%-6d tid=%-6d fd=%-3d bytes=%-6d comm=%s",
			name, e.Pid, e.Tid, e.Fd, e.Bytes, comm)
		if e.PayloadLen > 0 {
			n := int(e.PayloadLen)
			if n > len(e.Payload) {
				n = len(e.Payload)
			}
			line += " | " + renderPayload(e.Payload[:n])
		}
		log.Println(line)

		for _, h := range parser.Feed(&e) {
			log.Println(http.RenderMessage(h))
			if pe, ok := pairer.Push(h); ok {
				log.Println(http.RenderPaired(pe, anchor.WallTime(pe.ReqTsNs)))
			}
		}
		if e.Syscall == events.SyscallClose {
			parser.Close(e.Pid, e.Fd)
			pairer.Close(e.Pid, e.Fd)
		}
	}
}

// renderPayload turns a raw byte slice into a single-line printable string.
// Printable ASCII (0x20–0x7E) is kept as-is; CR/LF/TAB are escaped so the
// log stays on one line; everything else becomes `.`.
func renderPayload(p []byte) string {
	out := make([]byte, 0, len(p)+8)
	for _, b := range p {
		switch {
		case b == '\r':
			out = append(out, '\\', 'r')
		case b == '\n':
			out = append(out, '\\', 'n')
		case b == '\t':
			out = append(out, '\\', 't')
		case b >= 0x20 && b <= 0x7e:
			out = append(out, b)
		default:
			out = append(out, '.')
		}
	}
	return string(out)
}
