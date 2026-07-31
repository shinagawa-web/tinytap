package tls

import "github.com/shinagawa-web/tinytap/internal/events"

// FromSSL translates a plaintext capture from the SSL_write/SSL_read uprobe
// (#146) into the same events.Event shape the plaintext syscall capture path
// produces, using fd already resolved via SSL_set_fd correlation (#147,
// loader.SSLFdProbe.Lookup). ok is false when e.Op is not a supported SSL op
// (events.SSLOpWrite / events.SSLOpRead); callers should drop the event
// rather than feed a zero-value Syscall through.
//
// This exists so a single SSL_write()/SSL_read() call at the application
// level maps to one Event, exactly like one write()/read() syscall does
// today — which means a logical HTTP message split across several
// SSL_write()/SSL_read() calls (headers and body in separate calls, or
// OpenSSL's partial-write mode) reassembles for free through the existing
// per-(pid, fd) stream accumulation in Parser.Feed. No new buffering logic
// is needed here; getting the shape and semantics of one event right is the
// whole job (#148 — see issue for why the originally-suspected "syscall
// splitting under a single SSL_write() call" turned out not to apply: this
// program reads the plaintext buffer directly, not from the underlying
// ciphertext syscalls).
//
// The returned Event must be fed to a Parser instance dedicated to
// TLS-observed traffic, never the same Parser handling this process's
// plaintext syscall captures: both would share the same (pid, fd) connKey,
// and ciphertext bytes from the ordinary syscall capture would corrupt the
// plaintext stream this event contributes to.
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
