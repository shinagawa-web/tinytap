package tls

import "github.com/shinagawa-web/tinytap/internal/events"

func FromSSL(e *events.SSLEvent, fd int32) (events.Event, bool) {
	var syscall uint32
	switch e.Op {
	case events.SSLOpWrite:
		syscall = events.SyscallWrite
	case events.SSLOpRead:
		syscall = events.SyscallRead
	default:
		return events.Event{}, false
	}

	return events.Event{
		TsNs:       e.TsNs,
		Pid:        e.Pid,
		Tid:        e.Tid,
		Fd:         fd,
		Bytes:      e.Len,
		Syscall:    syscall,
		PayloadLen: e.PayloadLen,
		Comm:       e.Comm,
		Payload:    e.Payload,
	}, true
}
