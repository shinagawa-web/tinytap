package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// HTTPParser reassembles HTTP/1.x messages from per-direction byte streams
// observed in BPF events. One stream per (pid, fd, direction). A stream
// can carry multiple messages in sequence (HTTP/1.1 keep-alive), so on
// body completion the state resets to look for the next start line.
//
// Direction is taken from the syscall:
//   - read / recvfrom / recvmsg → incoming
//   - write / sendto / sendmsg → outgoing
//
// Discrimination between request and response is by the start line:
//   - "GET / HTTP/1.1"      → request
//   - "HTTP/1.0 200 OK"     → response
//
// Body length comes from Content-Length. Chunked encoding is out of
// scope for #14 (deferred). Messages with no Content-Length header are
// treated as having a zero-byte body.

type httpParseState int

const (
	stateNeedStartLine httpParseState = iota
	stateNeedHeaders
	stateNeedBody
)

type direction int

const (
	dirIncoming direction = iota
	dirOutgoing
)

type connKey struct {
	pid uint32
	fd  int32
	dir direction
}

type httpRequestLine struct {
	method, path, version string
}

type httpStatusLine struct {
	version, reason string
	status          int
}

// maxBufBytes caps how much a stream may buffer before we decide it is
// not HTTP and stop processing it. Real HTTP/1.1 headers are bounded
// (most clients reject > 8 KiB); going past 16 KiB without finding a
// recognisable start line or header terminator means this fd carries
// some other byte stream (a log pipe, a binary file, …).
const maxBufBytes = 16 * 1024

// stream holds parser state for one direction of one (pid, fd).
type stream struct {
	buf           []byte
	state         httpParseState
	abandoned     bool // marked true if buf grew past maxBufBytes without progress
	isRequest     bool // set when the start line is parsed
	contentLength int
	bodyRemaining int
	req           httpRequestLine
	res           httpStatusLine
}

// HTTPEvent is what the parser emits when a message's headers are
// recognised. Body completion is tracked internally for keep-alive
// framing but doesn't produce a separate event.
type HTTPEvent struct {
	Pid       uint32
	Comm      string
	IsRequest bool
	Req       httpRequestLine
	Res       httpStatusLine
}

type HTTPParser struct {
	streams map[connKey]*stream
}

func NewHTTPParser() *HTTPParser {
	return &HTTPParser{streams: make(map[connKey]*stream)}
}

// Feed processes a BPF event. Returns the HTTP events whose headers
// completed during this call (zero, one, or more if a stream contained
// multiple pipelined messages).
func (p *HTTPParser) Feed(e *Event) []HTTPEvent {
	var dir direction
	switch e.Syscall {
	case syscallRead, syscallRecvfrom, syscallRecvmsg:
		dir = dirIncoming
	case syscallWrite, syscallSendto, syscallSendmsg:
		dir = dirOutgoing
	default:
		return nil
	}

	if e.PayloadLen == 0 {
		return nil
	}

	n := int(e.PayloadLen)
	if n > len(e.Payload) {
		n = len(e.Payload)
	}
	payload := e.Payload[:n]

	key := connKey{pid: e.Pid, fd: e.Fd, dir: dir}
	s, ok := p.streams[key]
	if !ok {
		s = &stream{}
		p.streams[key] = s
	}
	// Once a stream is recognised as non-HTTP, drop further bytes for it
	// instead of recreating state on every event. The marker entry stays
	// in the map until the fd is closed.
	if s.abandoned {
		return nil
	}
	s.buf = append(s.buf, payload...)

	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	out := p.advance(s, e.Pid, comm)

	// If the stream is accumulating without finding HTTP structure, abandon
	// it so it cannot grow unbounded. State machine in stateNeedBody drains
	// buf as it goes, so this cap is only reached during start-line / header
	// scanning of a stream that almost certainly is not HTTP.
	if len(s.buf) > maxBufBytes {
		s.abandoned = true
		s.buf = nil
	}
	return out
}

// Close evicts both directions for the given (pid, fd). Pending data
// (an incomplete message) is dropped silently.
func (p *HTTPParser) Close(pid uint32, fd int32) {
	delete(p.streams, connKey{pid: pid, fd: fd, dir: dirIncoming})
	delete(p.streams, connKey{pid: pid, fd: fd, dir: dirOutgoing})
}

// advance drives the state machine until the buffer is drained or more
// bytes are needed. Each completed header set produces one HTTPEvent.
func (p *HTTPParser) advance(s *stream, pid uint32, comm string) []HTTPEvent {
	var out []HTTPEvent
	for {
		switch s.state {
		case stateNeedStartLine:
			idx := bytes.Index(s.buf, []byte("\r\n"))
			if idx < 0 {
				return out
			}
			line := string(s.buf[:idx])
			s.buf = s.buf[idx+2:]

			if strings.HasPrefix(line, "HTTP/") {
				parts := strings.SplitN(line, " ", 3)
				if len(parts) < 2 {
					return out // malformed; give up on this stream until next message
				}
				status, err := strconv.Atoi(parts[1])
				if err != nil {
					return out
				}
				reason := ""
				if len(parts) == 3 {
					reason = parts[2]
				}
				s.isRequest = false
				s.res = httpStatusLine{version: parts[0], status: status, reason: reason}
			} else {
				parts := strings.SplitN(line, " ", 3)
				if len(parts) < 3 || !strings.HasPrefix(parts[2], "HTTP/") {
					return out
				}
				s.isRequest = true
				s.req = httpRequestLine{method: parts[0], path: parts[1], version: parts[2]}
			}
			s.contentLength = 0
			s.state = stateNeedHeaders

		case stateNeedHeaders:
			idx := bytes.Index(s.buf, []byte("\r\n\r\n"))
			if idx < 0 {
				return out
			}
			headerBlock := string(s.buf[:idx])
			s.buf = s.buf[idx+4:]

			for _, h := range strings.Split(headerBlock, "\r\n") {
				colon := strings.Index(h, ":")
				if colon < 0 {
					continue
				}
				name := strings.TrimSpace(h[:colon])
				value := strings.TrimSpace(h[colon+1:])
				if strings.EqualFold(name, "Content-Length") {
					// Ignore negative or unparseable values; a hostile or buggy
					// origin sending Content-Length: -1 would otherwise set
					// bodyRemaining < 0 and crash stateNeedBody on s.buf[consume:].
					if n, err := strconv.Atoi(value); err == nil && n >= 0 {
						s.contentLength = n
					}
				}
			}

			out = append(out, HTTPEvent{
				Pid:       pid,
				Comm:      comm,
				IsRequest: s.isRequest,
				Req:       s.req,
				Res:       s.res,
			})

			s.bodyRemaining = s.contentLength
			if s.bodyRemaining == 0 {
				s.state = stateNeedStartLine
			} else {
				s.state = stateNeedBody
			}

		case stateNeedBody:
			consume := s.bodyRemaining
			if consume > len(s.buf) {
				consume = len(s.buf)
			}
			s.bodyRemaining -= consume
			s.buf = s.buf[consume:]
			if s.bodyRemaining > 0 {
				return out
			}
			s.state = stateNeedStartLine
		}
	}
}

func renderHTTPEvent(e HTTPEvent) string {
	if e.IsRequest {
		return fmt.Sprintf("request  pid=%-6d comm=%-16s method=%-6s path=%s version=%s",
			e.Pid, e.Comm, e.Req.method, e.Req.path, e.Req.version)
	}
	return fmt.Sprintf("response pid=%-6d comm=%-16s version=%s status=%d reason=%s",
		e.Pid, e.Comm, e.Res.version, e.Res.status, e.Res.reason)
}
