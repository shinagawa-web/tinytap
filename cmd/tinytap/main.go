// Command tinytap attaches the BPF program, drains its ringbuf, parses
// the per-syscall events into HTTP messages, pairs requests with
// responses, and feeds the result to an output sink.
//
// Everything beyond this file is in internal/: the BPF lifecycle in
// internal/loader, the event struct + decode in internal/events,
// per-protocol parsing under internal/protocols/, and output rendering
// under internal/output/. main.go only wires them together.
package main

import (
	"errors"
	"fmt"
	"os"
)

var osExit = os.Exit
var runner = run

var errSilentExit = errors.New("silent exit")

func main() {
	if err := runner(); err != nil {
		if !errors.Is(err, errSilentExit) {
			fmt.Fprintln(os.Stderr, err)
		}
		osExit(1)
	}
}
