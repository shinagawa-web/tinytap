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

// pidFd identifies a connection across both directions. Used to thread
// request-side state (e.g., the request method) over to the response side
// for framing decisions like "HEAD responses have no body".
type pidFd struct {
	pid uint32
	fd  int32
}

// stream holds parser state for one direction of one (pid, fd).
type stream struct {
	fd            int32 // copied from connKey so advance() can do per-pidFd lookups
	buf           []byte
	state         httpParseState
	abandoned     bool // marked true if buf grew past maxBufBytes without progress
	isRequest     bool // set when the start line is parsed
	contentLength int
	bodyRemaining int // wire bytes of body still to drain (not sample bytes)
	req           httpRequestLine
	res           httpStatusLine
	// wireBytesSinceMessageStart sums Event.Bytes for events whose payload
	// has been appended to buf since the current message's start. At the
	// header→body transition we subtract wireBytesConsumed to recover how
	// many wire bytes of body have already been seen — necessary because
	// payload samples are capped at MAX_PAYLOAD (256), so buf length and
	// wire length diverge for any syscall larger than that.
	wireBytesSinceMessageStart int
	// wireBytesConsumed is the wire-byte length of buf slices consumed by
	// start-line + headers parsing for the current message. Buf positions
	// map 1:1 to wire positions for the consumed prefix (a truncation gap
	// inside that prefix would have prevented header parsing from finding
	// the terminator), so this counter is exact for the common path.
	wireBytesConsumed int
	// messageStartTs is the BPF timestamp of the first event that
	// contributed bytes to the current message. Used as the HTTPEvent's
	// timestamp, and as the basis for latency once a response is paired
	// with its request.
	messageStartTs uint64
}

// HTTPEvent is what the parser emits when a message's headers are
// recognised. Body completion is tracked internally for keep-alive
// framing but doesn't produce a separate event.
type HTTPEvent struct {
	TsNs          uint64 // first-byte timestamp of this message (BPF ktime ns)
	Pid           uint32
	Fd            int32 // file descriptor — pairs request with response on the same socket
	Comm          string
	IsRequest     bool
	Req           httpRequestLine
	Res           httpStatusLine
	ContentLength int // body length as advertised by Content-Length (post-no-body override)
}

type HTTPParser struct {
	streams map[connKey]*stream
	// pendingMethods is a per-(pid, fd) FIFO of request methods awaiting
	// their response. Used so the response-side parser can frame the body
	// correctly when the request was a HEAD (response has no body even
	// when Content-Length is present, per RFC 7230 §3.3.3).
	pendingMethods map[pidFd][]string
}

func NewHTTPParser() *HTTPParser {
	return &HTTPParser{
		streams:        make(map[connKey]*stream),
		pendingMethods: make(map[pidFd][]string),
	}
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

	if e.Bytes == 0 {
		return nil
	}

	key := connKey{pid: e.Pid, fd: e.Fd, dir: dir}
	s, ok := p.streams[key]
	if !ok {
		s = &stream{fd: e.Fd}
		p.streams[key] = s
	}
	// Once a stream is recognised as non-HTTP, drop further bytes for it
	// instead of recreating state on every event. The marker entry stays
	// in the map until the fd is closed.
	if s.abandoned {
		return nil
	}

	n := int(e.PayloadLen)
	if n > len(e.Payload) {
		n = len(e.Payload)
	}
	payload := e.Payload[:n]
	wireBytes := int(e.Bytes)

	var out []HTTPEvent

	// If the stream is mid-body, debit wire bytes from bodyRemaining first.
	// We don't append the body to buf — body content is opaque to this
	// parser, and accumulating it would defeat the maxBufBytes cap on long
	// keep-alive streams.
	if s.state == stateNeedBody {
		debit := wireBytes
		if debit > s.bodyRemaining {
			debit = s.bodyRemaining
		}
		s.bodyRemaining -= debit
		// Trim the body portion off the sample. The first `debit` wire bytes
		// of this event are body; sample positions [0..debit) correspond to
		// those wire positions when debit <= len(payload).
		if debit < len(payload) {
			payload = payload[debit:]
		} else {
			payload = nil
		}
		wireBytes -= debit
		if s.bodyRemaining > 0 {
			return out
		}
		// Body drained; any leftover wire/sample bytes are the next message.
		// Reset messageStartTs to 0; either the carry-over append below
		// (next-message bytes in this event) will reseed it via the
		// "if messageStartTs == 0" check, or the next Feed call will.
		s.state = stateNeedStartLine
		s.wireBytesSinceMessageStart = 0
		s.wireBytesConsumed = 0
		s.messageStartTs = 0
	}

	if wireBytes == 0 {
		return out
	}

	// First event of a new message — capture its timestamp so HTTPEvent.TsNs
	// reflects when bytes first hit the wire (not when headers finished
	// arriving). messageStartTs is reset alongside wireBytesSinceMessageStart
	// whenever a message completes, so a zero value identifies a fresh stream
	// or a fresh post-body state.
	if s.messageStartTs == 0 {
		s.messageStartTs = e.TsNs
	}

	s.buf = append(s.buf, payload...)
	s.wireBytesSinceMessageStart += wireBytes

	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	out = append(out, p.advance(s, e.Pid, comm, e.TsNs)...)

	// If the stream is accumulating without finding HTTP structure, abandon
	// it so it cannot grow unbounded. Body draining above never touches buf,
	// so this cap is only reached during start-line / header scanning of a
	// stream that almost certainly is not HTTP.
	if len(s.buf) > maxBufBytes {
		s.abandoned = true
		s.buf = nil
	}
	return out
}

// Close evicts both directions for the given (pid, fd). Pending data
// (an incomplete message, or queued request methods awaiting a response
// that will never arrive) is dropped silently.
func (p *HTTPParser) Close(pid uint32, fd int32) {
	delete(p.streams, connKey{pid: pid, fd: fd, dir: dirIncoming})
	delete(p.streams, connKey{pid: pid, fd: fd, dir: dirOutgoing})
	delete(p.pendingMethods, pidFd{pid: pid, fd: fd})
}

// advance drives the state machine until the buffer is drained or more
// bytes are needed. Each completed header set produces one HTTPEvent.
// currentEventTs is the BPF ktime of the event Feed is currently
// processing — used to seed the next message's messageStartTs when a
// pipelined message's bytes carry over from the same event.
func (p *HTTPParser) advance(s *stream, pid uint32, comm string, currentEventTs uint64) []HTTPEvent {
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
			s.wireBytesConsumed += idx + 2

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
			// The header section ends at the empty line that follows it.
			// In wire form that empty line is `\r\n` immediately *after*
			// the previous line's `\r\n` — i.e. `\r\n\r\n` straddling the
			// boundary. The start-line state already consumed the
			// boundary's first `\r\n`, so we now expect either:
			//   - `\r\n` at the very start of buf → zero headers
			//   - `<header lines>\r\n\r\n` somewhere in buf → some headers
			// Without the zero-headers case, responses like `HTTP/1.1 100
			// Continue\r\n\r\n` (no header lines) stall the parser.
			var headerBlock string
			var consume int
			if len(s.buf) >= 2 && s.buf[0] == '\r' && s.buf[1] == '\n' {
				headerBlock = ""
				consume = 2
			} else {
				idx := bytes.Index(s.buf, []byte("\r\n\r\n"))
				if idx < 0 {
					return out
				}
				headerBlock = string(s.buf[:idx])
				consume = idx + 4
			}
			s.buf = s.buf[consume:]
			s.wireBytesConsumed += consume

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

			// Determine whether the response actually has a body (RFC 7230
			// §3.3.3). Requests are tracked on a per-(pid, fd) FIFO so the
			// response side can recognise that a HEAD's response carries no
			// body regardless of Content-Length. Done before emitting so
			// HTTPEvent.ContentLength reflects the *effective* body size.
			//
			// 1xx responses are *informational* — they precede a final
			// response for the same request (e.g. "100 Continue" before a
			// "201 Created"). Pop the queued method only on final responses
			// (>=200); for 1xx peek so the method stays available for the
			// final reply. Otherwise pipelined HEAD requests get
			// desynchronised when a prior request emits a 1xx.
			key := pidFd{pid: pid, fd: s.fd}
			if s.isRequest {
				p.pendingMethods[key] = append(p.pendingMethods[key], s.req.method)
			} else {
				var method string
				if s.res.status >= 200 {
					method = p.popMethod(key)
				} else {
					method = p.peekMethod(key)
				}
				if hasNoBody(s.res.status, method) {
					s.contentLength = 0
				}
			}

			out = append(out, HTTPEvent{
				TsNs:          s.messageStartTs,
				Pid:           pid,
				Fd:            s.fd,
				Comm:          comm,
				IsRequest:     s.isRequest,
				Req:           s.req,
				Res:           s.res,
				ContentLength: s.contentLength,
			})

			// Recover how much of the body has already arrived in wire bytes.
			// Buf positions consumed by start-line + headers map 1:1 to wire
			// positions (a truncation gap inside that prefix would have
			// prevented finding the terminator); the leftover wire bytes are
			// body that's already been delivered.
			bodyAlready := s.wireBytesSinceMessageStart - s.wireBytesConsumed
			if bodyAlready < 0 {
				bodyAlready = 0
			}

			if bodyAlready >= s.contentLength {
				// Body fully covered by events already in buf. Any extra
				// sample bytes belong to the next pipelined message.
				bodyInBuf := s.contentLength
				if bodyInBuf > len(s.buf) {
					bodyInBuf = len(s.buf)
				}
				s.buf = s.buf[bodyInBuf:]
				s.bodyRemaining = 0
				s.state = stateNeedStartLine
				s.wireBytesSinceMessageStart = bodyAlready - s.contentLength
				s.wireBytesConsumed = 0
				// If carry-over buf bytes belong to the next message, they
				// came in via the event Feed is currently processing — the
				// same syscall that carried this message's body tail — so
				// the next message's first byte hit the wire at the same
				// TsNs. Without this, advance() loops into the next
				// start-line and emits an HTTPEvent with TsNs==0, breaking
				// latency. When buf is empty, the next message will arrive
				// in a future event; reset to 0 so Feed reseeds it then.
				if len(s.buf) > 0 {
					s.messageStartTs = currentEventTs
				} else {
					s.messageStartTs = 0
				}
			} else {
				// Body still draining — subsequent events are debited via
				// Feed's wire-byte accounting. Drop body sample bytes; we
				// no longer need buf until the next start line.
				s.bodyRemaining = s.contentLength - bodyAlready
				s.buf = nil
				s.state = stateNeedBody
				s.wireBytesSinceMessageStart = 0
				s.wireBytesConsumed = 0
				return out
			}

		case stateNeedBody:
			// Body draining is handled in Feed via wire-byte accounting; the
			// state machine only re-enters this branch defensively when an
			// internal contract is violated.
			return out
		}
	}
}

// popMethod pulls the next pending request method for the given (pid, fd).
// Returns "" if no request has been seen — which happens when the parser
// started mid-stream (responses observed without their request) or when
// the request was on a connection we did not capture from.
func (p *HTTPParser) popMethod(key pidFd) string {
	q := p.pendingMethods[key]
	if len(q) == 0 {
		return ""
	}
	m := q[0]
	if len(q) == 1 {
		delete(p.pendingMethods, key)
	} else {
		p.pendingMethods[key] = q[1:]
	}
	return m
}

// peekMethod returns the next pending request method without dequeuing.
// Used for 1xx informational responses, where the same request will be
// followed by a final response (>=200) that still needs the method.
func (p *HTTPParser) peekMethod(key pidFd) string {
	q := p.pendingMethods[key]
	if len(q) == 0 {
		return ""
	}
	return q[0]
}

// hasNoBody reports whether a response with the given status, sent in
// reply to the given method, is required by HTTP/1.1 framing to have an
// empty body regardless of any Content-Length header. Method may be ""
// when the request side was missed; in that case only the status is
// checked. RFC 7230 §3.3.3.
func hasNoBody(status int, method string) bool {
	if method == "HEAD" {
		return true
	}
	if status >= 100 && status < 200 {
		return true
	}
	return status == 204 || status == 304
}

func renderHTTPEvent(e HTTPEvent) string {
	if e.IsRequest {
		return fmt.Sprintf("request  pid=%-6d comm=%-16s method=%-6s path=%s version=%s",
			e.Pid, e.Comm, e.Req.method, e.Req.path, e.Req.version)
	}
	return fmt.Sprintf("response pid=%-6d comm=%-16s version=%s status=%d reason=%s",
		e.Pid, e.Comm, e.Res.version, e.Res.status, e.Res.reason)
}
