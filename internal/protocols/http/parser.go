package http

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/shinagawa-web/tinytap/internal/events"
)

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
	pid         uint32
	fd          int32
	ssl         uint64
	sslFallback bool
	dir         direction
}

type httpRequestLine struct {
	method, path, version string
}

type httpStatusLine struct {
	version, reason string
	status          int
}

const maxBufBytes = 16 * 1024 // most HTTP/1.1 clients reject headers > 8 KiB
const maxBodyBytes = 16 * 1024

type pendingKey struct {
	pid         uint32
	fd          int32
	ssl         uint64
	sslFallback bool
}

type stream struct {
	fd                         int32
	ssl                        uint64
	sslFallback                bool
	buf                        []byte
	state                      httpParseState
	abandoned                  bool
	isRequest                  bool
	chunked                    bool
	chunkRemaining             int
	contentLength              int
	bodyRemaining              int
	req                        httpRequestLine
	res                        httpStatusLine
	bodyBuf                    []byte
	bodyTruncated              bool
	pendingMsg                 Message
	pendingValid               bool
	wireBytesSinceMessageStart int
	wireBytesConsumed          int
	messageStartTs             uint64
}

type Message struct {
	TsNs          uint64
	Pid           uint32
	Fd            int32
	Comm          string
	IsRequest     bool
	Req           httpRequestLine
	Res           httpStatusLine
	ContentLength int
	Headers       []Header
	BodySample    []byte
	BodyTruncated bool
	SSL           uint64
	SSLFallback   bool
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Parser struct {
	streams         map[connKey]*stream
	pendingMethods  map[pendingKey][]string
	resolve         func(pid uint32) string
	HeaderLossCount int
}

func NewParser() *Parser {
	return &Parser{
		streams:        make(map[connKey]*stream),
		pendingMethods: make(map[pendingKey][]string),
	}
}

func NewParserWithResolve(resolve func(pid uint32) string) *Parser {
	p := NewParser()
	p.resolve = resolve
	return p
}

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

	n := int(e.PayloadLen)
	if n > len(e.Payload) {
		n = len(e.Payload)
	}
	comm := p.resolveComm(e.Pid, e.Comm)
	return p.feed(s, e.Pid, comm, e.TsNs, e.Payload[:n], int(e.Bytes))
}

func (p *Parser) FeedSSL(e *events.SSLEvent) []Message {
	var dir direction
	switch e.Op {
	case events.SSLOpRead:
		dir = dirIncoming
	case events.SSLOpWrite:
		dir = dirOutgoing
	default:
		return nil
	}

	if e.Len == 0 {
		return nil
	}

	key := connKey{pid: e.Pid, ssl: e.SSL, sslFallback: true, dir: dir}
	s, ok := p.streams[key]
	if !ok {
		s = &stream{ssl: e.SSL, sslFallback: true}
		p.streams[key] = s
	}

	n := int(e.PayloadLen)
	if n > len(e.Payload) {
		n = len(e.Payload)
	}
	comm := p.resolveComm(e.Pid, e.Comm)
	return p.feed(s, e.Pid, comm, e.TsNs, e.Payload[:n], int(e.Len))
}

func (p *Parser) resolveComm(pid uint32, fallback [16]byte) string {
	if p.resolve != nil {
		if comm := p.resolve(pid); comm != "" {
			return comm
		}
	}
	return string(bytes.TrimRight(fallback[:], "\x00"))
}

func (p *Parser) feed(s *stream, pid uint32, comm string, tsNs uint64, payload []byte, wireBytes int) []Message {
	if s.abandoned {
		return nil
	}

	var out []Message

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

	if s.state == stateNeedBody {
		debit := wireBytes
		if debit > s.bodyRemaining {
			debit = s.bodyRemaining
		}
		s.bodyRemaining -= debit
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
		if s.pendingValid {
			out = append(out, s.takeBody(s.pendingMsg))
		}
		s.state = stateNeedStartLine
		s.wireBytesSinceMessageStart = 0
		s.wireBytesConsumed = 0
		s.messageStartTs = 0
	}

	if wireBytes == 0 {
		return out
	}

	if s.messageStartTs == 0 {
		s.messageStartTs = tsNs
	}

	s.buf = append(s.buf, payload...)
	s.wireBytesSinceMessageStart += wireBytes

	out = append(out, p.advance(s, pid, comm, tsNs)...)

	if s.state == stateNeedStartLine || s.state == stateNeedHeaders {
		// gap in buf: discard and resynchronise rather than splice (#224)
		if s.wireBytesSinceMessageStart-s.wireBytesConsumed > len(s.buf) {
			p.HeaderLossCount++
			s.buf = nil
			s.state = stateNeedStartLine
			s.wireBytesSinceMessageStart = 0
			s.wireBytesConsumed = 0
			s.messageStartTs = 0
		}
	}

	if len(s.buf) > maxBufBytes {
		s.abandoned = true
		s.buf = nil
	}
	return out
}

func (p *Parser) Close(pid uint32, fd int32) {
	delete(p.streams, connKey{pid: pid, fd: fd, dir: dirIncoming})
	delete(p.streams, connKey{pid: pid, fd: fd, dir: dirOutgoing})
	delete(p.pendingMethods, pendingKey{pid: pid, fd: fd})
}

func (p *Parser) CloseSSL(pid uint32, ssl uint64) {
	delete(p.streams, connKey{pid: pid, ssl: ssl, sslFallback: true, dir: dirIncoming})
	delete(p.streams, connKey{pid: pid, ssl: ssl, sslFallback: true, dir: dirOutgoing})
	delete(p.pendingMethods, pendingKey{pid: pid, ssl: ssl, sslFallback: true})
}

// ClosePid drops every stream and pending-method entry for pid, regardless
// of fd/ssl/direction. Parser has no TTL sweep (unlike Pairer.Sweep), so
// callers that share one Parser across many pids — the uprobe capture path
// shares one per libssl inode (#327) — must call this when a pid exits
// without ever reaching SSL_free/close, or its entries leak forever.
func (p *Parser) ClosePid(pid uint32) {
	for k := range p.streams {
		if k.pid == pid {
			delete(p.streams, k)
		}
	}
	for k := range p.pendingMethods {
		if k.pid == pid {
			delete(p.pendingMethods, k)
		}
	}
}

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

func (s *stream) takeBody(msg Message) Message {
	msg.BodySample = s.bodyBuf
	msg.BodyTruncated = s.bodyTruncated
	s.bodyBuf = nil
	s.bodyTruncated = false
	s.pendingMsg = Message{}
	s.pendingValid = false
	return msg
}

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
					return out
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

			// RFC 7230 §3.3.3
			key := pendingKey{pid: pid, fd: s.fd, ssl: s.ssl, sslFallback: s.sslFallback}
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
					chunked = false
				}
			}
			s.chunked = chunked

			msg := Message{
				TsNs:          s.messageStartTs,
				Pid:           pid,
				Fd:            s.fd,
				SSL:           s.ssl,
				SSLFallback:   s.sslFallback,
				Comm:          comm,
				IsRequest:     s.isRequest,
				Req:           s.req,
				Res:           s.res,
				ContentLength: s.contentLength,
				Headers:       headers,
			}

			if s.chunked {
				s.pendingMsg = msg
				s.pendingValid = true
				s.state = stateNeedChunkSize
				continue
			}

			bodyAlready := s.wireBytesSinceMessageStart - s.wireBytesConsumed
			if bodyAlready < 0 {
				bodyAlready = 0
			}

			bodyInBuf := s.contentLength
			if bodyInBuf > len(s.buf) {
				bodyInBuf = len(s.buf)
			}
			s.appendBody(s.buf[:bodyInBuf])

			if bodyAlready >= s.contentLength {
				if bodyInBuf < s.contentLength {
					s.bodyTruncated = true
				}
				s.buf = s.buf[bodyInBuf:]
				s.bodyRemaining = 0
				s.state = stateNeedStartLine
				s.wireBytesSinceMessageStart = bodyAlready - s.contentLength
				s.wireBytesConsumed = 0
				out = append(out, s.takeBody(msg))
				if len(s.buf) > 0 {
					s.messageStartTs = currentEventTs
				} else {
					s.messageStartTs = 0
				}
			} else {
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
			return out

		case stateNeedChunkSize: // "HEX[;ext]\r\n" (RFC 7230 §4.1.1)
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
			if size64 > math.MaxInt32 { // would overflow int on 32-bit platforms
				s.abandoned = true
				s.buf = nil
				return out
			}
			chunkSize := int(size64)

			chunkDataArrived := s.wireBytesSinceMessageStart - s.wireBytesConsumed
			if chunkDataArrived < 0 {
				chunkDataArrived = 0
			}

			bodyInBuf := chunkSize
			if bodyInBuf > len(s.buf) {
				bodyInBuf = len(s.buf)
			}
			s.appendBody(s.buf[:bodyInBuf])

			if chunkDataArrived >= chunkSize {
				if bodyInBuf < chunkSize {
					s.bodyTruncated = true
				}
				s.buf = s.buf[bodyInBuf:]
				s.wireBytesConsumed += chunkSize
				s.state = stateNeedChunkCRLF
			} else {
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
			if len(s.buf) < 2 {
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

		case stateNeedTrailer: // RFC 7230 §4.1.2
			var trailerConsumed int
			if len(s.buf) >= 2 && s.buf[0] == '\r' && s.buf[1] == '\n' {
				trailerConsumed = 2
				s.buf = s.buf[2:]
			} else {
				tidx := bytes.Index(s.buf, []byte("\r\n\r\n"))
				if tidx < 0 {
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

func (p *Parser) popMethod(key pendingKey) string {
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

func (p *Parser) peekMethod(key pendingKey) string {
	q := p.pendingMethods[key]
	if len(q) == 0 {
		return ""
	}
	return q[0]
}

// RFC 7230 §3.3.3
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
