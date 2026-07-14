// Package http parses HTTP/1.x messages from BPF observation streams,
// pairs requests with responses on the same (pid, fd), and renders the
// one-line summary the demo emits. The package is protocol-specific —
// peers under internal/protocols/ (PostgreSQL, Redis, etc.) will mirror
// this shape rather than share code with it, because each protocol's
// framing and pairing semantics differ.
package http

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/shinagawa-web/tinytap/internal/events"
)

// Parser reassembles HTTP/1.x messages from per-direction byte streams
// observed in BPF events. One stream per (pid, fd, direction). A stream
// can carry multiple messages in sequence (HTTP/1.1 keep-alive), so on
// body completion the state resets to look for the next start line.
//
// Direction is taken from the syscall:
//   - read / recvfrom / recvmsg / readv → incoming
//   - write / sendto / sendmsg / writev / sendfile → outgoing
//
// Discrimination between request and response is by the start line:
//   - "GET / HTTP/1.1"      → request
//   - "HTTP/1.0 200 OK"     → response
//
// Body length comes from Content-Length or Transfer-Encoding: chunked.
// Messages with neither are treated as having a zero-byte body.

type httpParseState int

const (
	stateNeedStartLine httpParseState = iota
	stateNeedHeaders
	stateNeedBody
	stateNeedChunkSize // parse "HEX[;ext]\r\n"
	stateNeedChunkData // drain chunk wire bytes (Feed-side accounting)
	stateNeedChunkCRLF // consume "\r\n" after chunk data
	stateNeedTrailer   // consume optional trailer headers + final "\r\n"
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

// maxBodyBytes caps how many body bytes a single message retains (#35). A
// streamed upload or download can be megabytes; we keep a prefix so the detail
// panel has something to show without letting RSS track the largest exchange.
// Beyond it the body is marked truncated and further bytes are dropped.
const maxBodyBytes = 16 * 1024

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
	chunked       bool // Transfer-Encoding: chunked detected for this message
	chunkRemaining int // wire bytes of current chunk still to drain
	contentLength int
	bodyRemaining int // wire bytes of body still to drain (not sample bytes)
	req           httpRequestLine
	res           httpStatusLine
	// Body capture (#35). A message is emitted only once its body has fully
	// drained, so while bodyRemaining > 0 the parsed-but-bodyless message waits
	// in pendingMsg and body sample bytes accumulate in bodyBuf (capped at
	// maxBodyBytes). bodyTruncated records that some body bytes were lost.
	bodyBuf       []byte
	bodyTruncated bool
	pendingMsg    Message
	pendingValid  bool
	// wireBytesSinceMessageStart sums Event.Bytes for events whose payload
	// has been appended to buf since the current message's start. At the
	// header→body transition we subtract wireBytesConsumed to recover how
	// many wire bytes of body have already been seen — necessary because
	// payload samples are capped at events.MaxPayload, so buf length and
	// wire length diverge for any syscall larger than that.
	wireBytesSinceMessageStart int
	// wireBytesConsumed is the wire-byte length of buf slices consumed by
	// start-line + headers parsing for the current message. Buf positions
	// map 1:1 to wire positions for the consumed prefix (a truncation gap
	// inside that prefix would have prevented header parsing from finding
	// the terminator), so this counter is exact for the common path.
	wireBytesConsumed int
	// messageStartTs is the BPF timestamp of the first event that
	// contributed bytes to the current message. Used as the Message's
	// timestamp, and as the basis for latency once a response is paired
	// with its request.
	messageStartTs uint64
}

// Message is what the parser emits for one HTTP message. A message with a body
// is emitted once that body has fully drained, so BodySample is populated (#35);
// a body-less message (no Content-Length, or a no-body status/method) is emitted
// as soon as its headers are recognised. TsNs is always the first-byte
// timestamp regardless of emission timing, so latency stays header-to-header.
type Message struct {
	TsNs          uint64 // first-byte timestamp of this message (BPF ktime ns)
	Pid           uint32
	Fd            int32 // file descriptor — pairs request with response on the same socket
	Comm          string
	IsRequest     bool
	Req           httpRequestLine
	Res           httpStatusLine
	ContentLength int      // body length as advertised by Content-Length (post-no-body override)
	Headers       []Header // request/response headers in on-wire order
	// BodySample is the captured body bytes, up to maxBodyBytes per message and
	// bounded per syscall by the BPF MaxPayload sample cap (#35). BodyTruncated
	// is set when any body bytes were lost — either a single syscall exceeded
	// the sample cap (wire-only tail) or the body exceeded maxBodyBytes.
	BodySample    []byte
	BodyTruncated bool
	// SSL and SSLFallback support pairing TLS-sourced messages that have no
	// verified fd (#171): some clients (curl, confirmed in #167) never call
	// SSL_set_fd, so the SSL_write/SSL_read uprobe (#146) plaintext can only
	// be identified by its SSL* pointer, not a socket fd. SSLFallback's zero
	// value (false) is today's default — every message currently produced by
	// Feed is fd-sourced. A future TLS event source (#149) sets SSLFallback
	// true and SSL to the observed pointer when no SSL_set_fd correlation
	// exists for it; Fd is meaningless in that case. Never both false/set and
	// true/unset — see Pairer, which keys strictly on one or the other and
	// never guesses a fd for an SSLFallback message.
	SSL         uint64
	SSLFallback bool
}

// Header is a single HTTP header field as it appeared on the wire. Name and
// Value are trimmed of surrounding whitespace but otherwise unmodified — no
// canonicalisation or lowercasing, so the detail panel shows exactly what was
// sent. Order is preserved (the slice mirrors wire order).
type Header struct {
	Name  string
	Value string
}

type Parser struct {
	streams map[connKey]*stream
	// pendingMethods is a per-(pid, fd) FIFO of request methods awaiting
	// their response. Used so the response-side parser can frame the body
	// correctly when the request was a HEAD (response has no body even
	// when Content-Length is present, per RFC 7230 §3.3.3).
	pendingMethods map[pidFd][]string
	// resolve maps a PID to a display name. When non-nil it is called
	// instead of reading Comm from the BPF event, so callers can supply
	// the full cmdline (e.g. "python3 manage.py runserver") in place of
	// the kernel's 15-char truncated task name.
	resolve func(pid uint32) string
}

func NewParser() *Parser {
	return &Parser{
		streams:        make(map[connKey]*stream),
		pendingMethods: make(map[pidFd][]string),
	}
}

// NewParserWithResolve returns a Parser that calls resolve(pid) to obtain the
// process display name. Falls back to the BPF event's Comm field when resolve
// returns "".
func NewParserWithResolve(resolve func(pid uint32) string) *Parser {
	p := NewParser()
	p.resolve = resolve
	return p
}

// Feed processes a BPF event. Returns the HTTP events whose headers
// completed during this call (zero, one, or more if a stream contained
// multiple pipelined messages).
func (p *Parser) Feed(e *events.Event) []Message {
	var dir direction
	switch e.Syscall {
	case events.SyscallRead, events.SyscallRecvfrom, events.SyscallRecvmsg,
		events.SyscallReadv:
		dir = dirIncoming
	case events.SyscallWrite, events.SyscallSendto, events.SyscallSendmsg,
		events.SyscallWritev, events.SyscallSendfile:
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

	var out []Message

	// If the stream is mid-chunk, debit wire bytes from chunkRemaining first.
	// Same rationale as stateNeedBody: body bytes are opaque, so we account
	// for them by wire count rather than buffering. Both wireBytesConsumed and
	// wireBytesSinceMessageStart are advanced by the debit so that the
	// chunkDataArrived formula in advance() stays consistent across events.
	if s.state == stateNeedChunkData {
		debit := wireBytes
		if debit > s.chunkRemaining {
			debit = s.chunkRemaining
		}
		s.chunkRemaining -= debit
		s.wireBytesConsumed += debit
		s.wireBytesSinceMessageStart += debit
		bodyInSample := debit
		if bodyInSample > len(payload) {
			bodyInSample = len(payload)
		}
		s.appendBody(payload[:bodyInSample])
		if debit > bodyInSample {
			s.bodyTruncated = true
		}
		if debit < len(payload) {
			payload = payload[debit:]
		} else {
			payload = nil
		}
		wireBytes -= debit
		if s.chunkRemaining > 0 {
			return out
		}
		s.state = stateNeedChunkCRLF
	}

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
		// Capture the body portion of this event's sample before trimming it
		// off. The first `debit` wire bytes of this event are body; the sample
		// carries the first min(debit, len(payload)) of them. If debit ran past
		// the sample, the syscall exceeded MaxPayload and the tail is wire-only
		// — mark the body truncated (#35).
		bodyInSample := debit
		if bodyInSample > len(payload) {
			bodyInSample = len(payload)
		}
		s.appendBody(payload[:bodyInSample])
		if debit > bodyInSample {
			s.bodyTruncated = true
		}
		if debit < len(payload) {
			payload = payload[debit:]
		} else {
			payload = nil
		}
		wireBytes -= debit
		if s.bodyRemaining > 0 {
			return out
		}
		// Body fully drained — emit the pending message with its body now.
		if s.pendingValid {
			out = append(out, s.takeBody(s.pendingMsg))
		}
		// Any leftover wire/sample bytes are the next message. Reset
		// messageStartTs to 0; either the carry-over append below (next-message
		// bytes in this event) will reseed it via the "if messageStartTs == 0"
		// check, or the next Feed call will.
		s.state = stateNeedStartLine
		s.wireBytesSinceMessageStart = 0
		s.wireBytesConsumed = 0
		s.messageStartTs = 0
	}

	if wireBytes == 0 {
		return out
	}

	// First event of a new message — capture its timestamp so Message.TsNs
	// reflects when bytes first hit the wire (not when headers finished
	// arriving). messageStartTs is reset alongside wireBytesSinceMessageStart
	// whenever a message completes, so a zero value identifies a fresh stream
	// or a fresh post-body state.
	if s.messageStartTs == 0 {
		s.messageStartTs = e.TsNs
	}

	s.buf = append(s.buf, payload...)
	s.wireBytesSinceMessageStart += wireBytes

	comm := ""
	if p.resolve != nil {
		comm = p.resolve(e.Pid)
	}
	if comm == "" {
		comm = string(bytes.TrimRight(e.Comm[:], "\x00"))
	}
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
func (p *Parser) Close(pid uint32, fd int32) {
	delete(p.streams, connKey{pid: pid, fd: fd, dir: dirIncoming})
	delete(p.streams, connKey{pid: pid, fd: fd, dir: dirOutgoing})
	delete(p.pendingMethods, pidFd{pid: pid, fd: fd})
}

// appendBody accumulates body sample bytes for the in-flight message, capped at
// maxBodyBytes. Hitting the cap (or appending past it) marks the body truncated.
func (s *stream) appendBody(p []byte) {
	if len(p) == 0 {
		return
	}
	room := maxBodyBytes - len(s.bodyBuf)
	if room <= 0 {
		s.bodyTruncated = true
		return
	}
	if len(p) > room {
		p = p[:room]
		s.bodyTruncated = true
	}
	s.bodyBuf = append(s.bodyBuf, p...)
}

// takeBody attaches the accumulated body to msg and resets the stream's body
// capture state, returning the completed message.
func (s *stream) takeBody(msg Message) Message {
	msg.BodySample = s.bodyBuf
	msg.BodyTruncated = s.bodyTruncated
	s.bodyBuf = nil
	s.bodyTruncated = false
	s.pendingMsg = Message{}
	s.pendingValid = false
	return msg
}

// advance drives the state machine until the buffer is drained or more
// bytes are needed. Each completed header set produces one Message.
// currentEventTs is the BPF ktime of the event Feed is currently
// processing — used to seed the next message's messageStartTs when a
// pipelined message's bytes carry over from the same event.
func (p *Parser) advance(s *stream, pid uint32, comm string, currentEventTs uint64) []Message {
	var out []Message
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

			var chunked bool
			var headers []Header
			for _, h := range strings.Split(headerBlock, "\r\n") {
				colon := strings.Index(h, ":")
				if colon < 0 {
					continue
				}
				name := strings.TrimSpace(h[:colon])
				value := strings.TrimSpace(h[colon+1:])
				headers = append(headers, Header{Name: name, Value: value})
				if strings.EqualFold(name, "Content-Length") {
					// Ignore negative or unparseable values; a hostile or buggy
					// origin sending Content-Length: -1 would otherwise set
					// bodyRemaining < 0 and crash stateNeedBody on s.buf[consume:].
					if n, err := strconv.Atoi(value); err == nil && n >= 0 {
						s.contentLength = n
					}
				}
				if strings.EqualFold(name, "Transfer-Encoding") {
					for _, enc := range strings.Split(value, ",") {
						if strings.EqualFold(strings.TrimSpace(enc), "chunked") {
							chunked = true
							break
						}
					}
				}
			}

			// Determine whether the response actually has a body (RFC 7230
			// §3.3.3). Requests are tracked on a per-(pid, fd) FIFO so the
			// response side can recognise that a HEAD's response carries no
			// body regardless of Content-Length. Done before emitting so
			// Message.ContentLength reflects the *effective* body size.
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
					chunked = false // no-body status overrides Transfer-Encoding
				}
			}
			s.chunked = chunked

			msg := Message{
				TsNs:          s.messageStartTs,
				Pid:           pid,
				Fd:            s.fd,
				Comm:          comm,
				IsRequest:     s.isRequest,
				Req:           s.req,
				Res:           s.res,
				ContentLength: s.contentLength,
				Headers:       headers,
			}

			if s.chunked {
				// Chunked body: park the header-complete message and start
				// consuming chunks. wireBytesConsumed already reflects the
				// start-line + headers; stateNeedChunkSize uses the same
				// wireBytesSinceMessageStart - wireBytesConsumed formula to
				// know how many chunk-data wire bytes have already arrived.
				s.pendingMsg = msg
				s.pendingValid = true
				s.state = stateNeedChunkSize
				// Fall through to stateNeedChunkSize in the same loop iteration.
				continue
			}

			// Content-Length path (existing logic).
			// Recover how much of the body has already arrived in wire bytes.
			// Buf positions consumed by start-line + headers map 1:1 to wire
			// positions (a truncation gap inside that prefix would have
			// prevented finding the terminator); the leftover wire bytes are
			// body that's already been delivered.
			bodyAlready := s.wireBytesSinceMessageStart - s.wireBytesConsumed
			if bodyAlready < 0 {
				bodyAlready = 0
			}

			// Capture the body bytes already sitting in buf (the body portion,
			// capped by what the samples carried). The message is emitted only
			// once its body has fully drained (#35) — a body delivered across
			// later syscalls is still attached — so until then it waits in
			// pendingMsg. A zero-body message (no Content-Length, or no-body
			// status/method) takes the bodyAlready >= contentLength branch with
			// an empty body and is emitted immediately.
			bodyInBuf := s.contentLength
			if bodyInBuf > len(s.buf) {
				bodyInBuf = len(s.buf)
			}
			s.appendBody(s.buf[:bodyInBuf])

			if bodyAlready >= s.contentLength {
				// Body fully covered by events already in buf. Any extra
				// sample bytes belong to the next pipelined message. If the
				// samples didn't carry the whole body (a syscall > MaxPayload),
				// the wire-only tail is lost — mark it truncated.
				if bodyInBuf < s.contentLength {
					s.bodyTruncated = true
				}
				s.buf = s.buf[bodyInBuf:]
				s.bodyRemaining = 0
				s.state = stateNeedStartLine
				s.wireBytesSinceMessageStart = bodyAlready - s.contentLength
				s.wireBytesConsumed = 0
				out = append(out, s.takeBody(msg))
				// If carry-over buf bytes belong to the next message, they
				// came in via the event Feed is currently processing — the
				// same syscall that carried this message's body tail — so
				// the next message's first byte hit the wire at the same
				// TsNs. Without this, advance() loops into the next
				// start-line and emits an Message with TsNs==0, breaking
				// latency. When buf is empty, the next message will arrive
				// in a future event; reset to 0 so Feed reseeds it then.
				if len(s.buf) > 0 {
					s.messageStartTs = currentEventTs
				} else {
					s.messageStartTs = 0
				}
			} else {
				// Body still draining — subsequent events are debited via
				// Feed's wire-byte accounting and appended to the pending
				// message. If the buf portion already dropped wire bytes (a
				// syscall > MaxPayload), mark it truncated now.
				if bodyAlready > bodyInBuf {
					s.bodyTruncated = true
				}
				s.bodyRemaining = s.contentLength - bodyAlready
				s.buf = nil
				s.state = stateNeedBody
				s.pendingMsg = msg
				s.pendingValid = true
				s.wireBytesSinceMessageStart = 0
				s.wireBytesConsumed = 0
				return out
			}

		case stateNeedBody:
			// Body draining is handled in Feed via wire-byte accounting; the
			// state machine only re-enters this branch defensively when an
			// internal contract is violated.
			return out

		case stateNeedChunkSize:
			// Parse "HEX[;ext]\r\n". Strip chunk extensions (RFC 7230 §4.1.1);
			// they carry no information relevant to framing.
			idx := bytes.Index(s.buf, []byte("\r\n"))
			if idx < 0 {
				return out
			}
			line := string(s.buf[:idx])
			if semi := strings.Index(line, ";"); semi >= 0 {
				line = line[:semi]
			}
			line = strings.TrimSpace(line)
			size64, err := strconv.ParseInt(line, 16, 64)
			if err != nil || size64 < 0 {
				s.abandoned = true
				s.buf = nil
				return out
			}
			s.wireBytesConsumed += idx + 2
			s.buf = s.buf[idx+2:]

			if size64 == 0 {
				s.state = stateNeedTrailer
				continue
			}
			if size64 > math.MaxInt32 {
				// Chunk sizes above MaxInt32 are implausible and would overflow
				// int on 32-bit platforms; abandon to avoid a potential panic.
				s.abandoned = true
				s.buf = nil
				return out
			}
			chunkSize := int(size64)

			// How many wire bytes of this chunk's data have already arrived?
			// wireBytesSinceMessageStart accumulates every event's Bytes;
			// wireBytesConsumed tracks all framing + drained chunk data bytes.
			// Their difference is the wire bytes still "unaccounted for",
			// i.e. chunk data that has arrived but not yet been consumed.
			chunkDataArrived := s.wireBytesSinceMessageStart - s.wireBytesConsumed
			if chunkDataArrived < 0 {
				chunkDataArrived = 0
			}

			// Capture the sample bytes available for this chunk from buf.
			bodyInBuf := chunkSize
			if bodyInBuf > len(s.buf) {
				bodyInBuf = len(s.buf)
			}
			s.appendBody(s.buf[:bodyInBuf])

			if chunkDataArrived >= chunkSize {
				// All wire bytes of this chunk have arrived. The sample may
				// be shorter than the chunk if any syscall exceeded MaxPayload.
				if bodyInBuf < chunkSize {
					s.bodyTruncated = true
				}
				s.buf = s.buf[bodyInBuf:]
				s.wireBytesConsumed += chunkSize
				s.state = stateNeedChunkCRLF
			} else {
				// Chunk still arriving across future events; Feed will debit
				// the remainder via stateNeedChunkData wire-byte accounting.
				if chunkDataArrived > bodyInBuf {
					s.bodyTruncated = true
				}
				s.buf = nil
				s.wireBytesConsumed += chunkDataArrived
				s.chunkRemaining = chunkSize - chunkDataArrived
				s.state = stateNeedChunkData
				return out
			}

		case stateNeedChunkCRLF:
			// Consume the "\r\n" that follows each chunk's data.
			if len(s.buf) < 2 {
				// If wire-byte accounting already shows at least 2 more
				// bytes arrived beyond what's been consumed, the CRLF made
				// it onto the wire even though the MaxPayload cap kept it
				// (or part of it) out of the sample. Trust that accounting
				// instead of abandoning — same model stateNeedBody already
				// uses for opaque body bytes (#116) — rather than stalling
				// forever waiting for bytes that will never appear in
				// s.buf. Any leftover byte already in s.buf is discarded
				// unvalidated along with it: this is a deliberate trade,
				// accepting that a non-compliant peer whose declared byte
				// count doesn't actually end in "\r\n" would be silently
				// mis-framed, in exchange for correctly pairing well-formed
				// exchanges regardless of chunk size. This branch itself
				// never sets BodyTruncated — it only skips 2 framing bytes,
				// not body content. BodyTruncated may already be true by
				// the time we get here (set earlier, by the chunk-data path
				// above, if the chunk's *data* didn't fully fit the
				// sample) or may still be false (if the data fit but only
				// this trailing CRLF was cut) — either way it accurately
				// reflects whether body content, specifically, was lost.
				if s.wireBytesSinceMessageStart-s.wireBytesConsumed >= 2 {
					s.wireBytesConsumed += 2
					s.buf = nil
					s.state = stateNeedChunkSize
					continue
				}
				return out
			}
			if s.buf[0] != '\r' || s.buf[1] != '\n' {
				s.abandoned = true
				s.buf = nil
				return out
			}
			s.wireBytesConsumed += 2
			s.buf = s.buf[2:]
			s.state = stateNeedChunkSize

		case stateNeedTrailer:
			// Trailer section: zero or more header fields followed by a blank
			// line. We ignore trailer field values (RFC 7230 §4.1.2 limits
			// what can appear there anyway).
			var trailerConsumed int
			if len(s.buf) >= 2 && s.buf[0] == '\r' && s.buf[1] == '\n' {
				trailerConsumed = 2
				s.buf = s.buf[2:]
			} else {
				tidx := bytes.Index(s.buf, []byte("\r\n\r\n"))
				if tidx < 0 {
					// Terminator not in sample. If wire bytes exceed what the
					// sample captured, the terminator was dropped by the
					// MaxPayload cap and will never appear in s.buf — abandon
					// to avoid a permanent stall.
					//
					// Unlike stateNeedChunkCRLF (#116), this can't be fixed
					// the same way: the trailer section has no fixed length,
					// so "more wire bytes arrived than the sample captured"
					// doesn't prove the terminator itself arrived — it could
					// just as easily mean a single trailer field is long
					// enough to exceed MaxPayload on its own and continues in
					// a later syscall, nowhere near the terminator yet.
					// Trusting that case would emit the message prematurely
					// and misframe every event after it (confirmed while
					// reviewing this fix — see PR #120 discussion). Properly
					// fixing this needs a way to tell "this sample was
					// truncated mid-trailer-field, more is coming" apart
					// from "the terminator specifically was dropped", which
					// stateNeedChunkCRLF gets for free from the chunk's
					// already-known size and this state does not. Left as a
					// separate, more carefully-scoped follow-up.
					if s.wireBytesSinceMessageStart-s.wireBytesConsumed > len(s.buf) {
						s.abandoned = true
						s.buf = nil
					}
					return out
				}
				trailerConsumed = tidx + 4
				s.buf = s.buf[trailerConsumed:]
			}
			s.wireBytesConsumed += trailerConsumed
			carryOver := s.wireBytesSinceMessageStart - s.wireBytesConsumed
			if carryOver < 0 {
				carryOver = 0
			}
			out = append(out, s.takeBody(s.pendingMsg))
			s.chunked = false
			s.chunkRemaining = 0
			s.state = stateNeedStartLine
			s.wireBytesSinceMessageStart = carryOver
			s.wireBytesConsumed = 0
			s.messageStartTs = 0
			if len(s.buf) > 0 {
				s.messageStartTs = currentEventTs
			}
		}
	}
}

// popMethod pulls the next pending request method for the given (pid, fd).
// Returns "" if no request has been seen — which happens when the parser
// started mid-stream (responses observed without their request) or when
// the request was on a connection we did not capture from.
func (p *Parser) popMethod(key pidFd) string {
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
func (p *Parser) peekMethod(key pidFd) string {
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

func RenderMessage(e Message) string {
	if e.IsRequest {
		return fmt.Sprintf("request  pid=%-6d comm=%-16s method=%-6s path=%s version=%s",
			e.Pid, e.Comm, e.Req.method, e.Req.path, e.Req.version)
	}
	return fmt.Sprintf("response pid=%-6d comm=%-16s version=%s status=%d reason=%s",
		e.Pid, e.Comm, e.Res.version, e.Res.status, e.Res.reason)
}
