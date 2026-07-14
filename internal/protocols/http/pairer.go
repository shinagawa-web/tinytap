package http

import "time"

const (
	AbandonReasonClosed  = "peer closed"
	AbandonReasonTimeout = "timed out"
)

// Pairer matches HTTP requests with their responses on the same connection
// identity and emits a single PairedEvent at the moment the response's
// headers arrive. Requests with no response yet stay queued; responses
// without a queued request are dropped (likely captured mid-stream).
//
// HTTP/1.1 keep-alive guarantees responses are returned in request order,
// so a simple FIFO per identity is sufficient. Chunked encoding and HTTP/2
// are out of scope for v0.1.0.
//
// Connection identity is normally (pid, fd). For TLS-sourced messages with
// no verified fd (Message.SSLFallback, #171) it is (pid, SSL*) instead — a
// dimension distinct from (pid, fd) by construction (see pairKey), so a
// fallback message can never collide with a real fd-keyed connection or
// with another SSL* on the same pid. Guessing or inferring a fd for these
// is explicitly rejected (#171): a wrong guess would silently cross-pair
// two unrelated exchanges, which is worse than the fallback path's own
// limitation of never receiving a Close() (see Close).
type Pairer struct {
	pending map[pairKey][]timedMessage
	now     func() time.Time
}

// pairKey identifies a connection for pairing purposes. sslFallback is an
// explicit discriminator, not inferred from fd/ssl being zero — so the
// fd-keyed and SSL-keyed halves of the key space can never collide by
// construction, regardless of what values fd or ssl happen to hold.
type pairKey struct {
	pid         uint32
	fd          int32  // meaningful only when sslFallback is false
	ssl         uint64 // meaningful only when sslFallback is true
	sslFallback bool
}

// keyFor derives a message's pairing identity. Zero-value Messages (every
// message Feed produces today) yield the same key shape the pairer has
// always used: {pid, fd}.
func keyFor(pid uint32, fd int32, ssl uint64, sslFallback bool) pairKey {
	if sslFallback {
		return pairKey{pid: pid, ssl: ssl, sslFallback: true}
	}
	return pairKey{pid: pid, fd: fd}
}

// timedMessage wraps a Message with the wall-clock time it arrived at the
// pairer, so Sweep can evict requests that have been pending too long.
type timedMessage struct {
	msg       Message
	arrivedAt time.Time
}

// PairedEvent is what the pairer hands off to the renderer once a request
// and response have been matched on the same (pid, fd). It carries every
// HTTP-level field the parser surfaced — even ones the default render
// line doesn't print — so future detail views (TUI row-expand, structured
// export) don't need to reach back into the parser layer.
//
// When Abandoned is true the event represents a request that never received
// a response; Status is 0 and AbandonReason describes why.
type PairedEvent struct {
	ReqTsNs       uint64        // request first-byte timestamp (BPF ktime ns)
	Latency       time.Duration // res.TsNs - req.TsNs, or elapsed wall time for abandoned
	Pid           uint32
	Fd            int32
	Comm          string
	Method        string
	Path          string
	ReqVersion    string // request start-line HTTP version (e.g. "HTTP/1.1")
	Status        int
	Reason        string   // response reason phrase (e.g. "OK", "Not Found")
	ResVersion    string   // response start-line HTTP version
	ResBytes      int      // response body bytes: Content-Length when present, else len(ResBody) (chunked)
	ReqBytes      int      // request body bytes: Content-Length when present, else len(ReqBody) (chunked)
	ReqHeaders    []Header // request headers in on-wire order
	ResHeaders    []Header // response headers in on-wire order
	Abandoned     bool     // true when the request never received a response
	AbandonReason string   // AbandonReasonClosed or AbandonReasonTimeout
	// Captured body samples (#35). Empty when the message carried no body.
	// *Truncated marks that some body bytes were lost (sample cap or budget).
	ReqBody          []byte
	ReqBodyTruncated bool
	ResBody          []byte
	ResBodyTruncated bool
	// SSL and SSLFallback mirror Message's fields of the same name (#171).
	// When SSLFallback is true, Fd carries no meaning — this pair was matched
	// on (Pid, SSL) instead, and renderers must show it as such rather than
	// display Fd as if it were verified.
	SSL         uint64
	SSLFallback bool
}

func NewPairer() *Pairer {
	return newPairerWithClock(time.Now)
}

func newPairerWithClock(now func() time.Time) *Pairer {
	return &Pairer{
		pending: make(map[pairKey][]timedMessage),
		now:     now,
	}
}

// Push registers an HTTP event with the pairer. If the event is a request,
// it is queued and nil is returned. If the event is a response and a
// matching request is queued, the request is dequeued and a paired event
// is returned. Unmatched responses (request was missed) yield nil so the
// caller can decide whether to render them on their own.
//
// A request and its response only pair when they carry the *same* identity
// kind: an SSLFallback request never pairs with an ordinary fd-keyed
// response even if their Pid/Fd/SSL values happened to coincide, and vice
// versa — keyFor's discriminator makes that impossible by construction.
//
// A malformed SSLFallback message (SSL == 0 — no producer should ever emit
// one, but Push does not trust that) is dropped rather than paired: keying
// it on (pid, ssl=0) would collapse every SSL* this pid ever fails to set
// onto one shared FIFO, reopening exactly the cross-pairing risk #171
// exists to close, just from a different bug than a guessed fd.
func (p *Pairer) Push(e Message) (PairedEvent, bool) {
	if e.SSLFallback && e.SSL == 0 {
		return PairedEvent{}, false
	}
	key := keyFor(e.Pid, e.Fd, e.SSL, e.SSLFallback)
	if e.IsRequest {
		p.pending[key] = append(p.pending[key], timedMessage{msg: e, arrivedAt: p.now()})
		return PairedEvent{}, false
	}
	q := p.pending[key]
	if len(q) == 0 {
		return PairedEvent{}, false
	}
	req := q[0].msg
	if len(q) == 1 {
		delete(p.pending, key)
	} else {
		p.pending[key] = q[1:]
	}
	return PairedEvent{
		ReqTsNs:    req.TsNs,
		Latency:    time.Duration(int64(e.TsNs) - int64(req.TsNs)),
		Pid:        req.Pid,
		Fd:         req.Fd,
		Comm:       req.Comm,
		Method:     req.Req.method,
		Path:       req.Req.path,
		ReqVersion: req.Req.version,
		Status:     e.Res.status,
		Reason:     e.Res.reason,
		ResVersion: e.Res.version,
		ResBytes:   bodyBytes(e.ContentLength, e.BodySample),
		ReqBytes:   bodyBytes(req.ContentLength, req.BodySample),
		ReqHeaders: req.Headers,
		ResHeaders: e.Headers,

		ReqBody:          req.BodySample,
		ReqBodyTruncated: req.BodyTruncated,
		ResBody:          e.BodySample,
		ResBodyTruncated: e.BodyTruncated,

		SSL:         req.SSL,
		SSLFallback: req.SSLFallback,
	}, true
}

// bodyBytes returns cl when cl is non-zero (Content-Length path), otherwise
// falls back to len(sample) for chunked responses that carry no Content-Length.
func bodyBytes(cl int, sample []byte) int {
	if cl != 0 {
		return cl
	}
	return len(sample)
}

// Close emits an abandoned PairedEvent for every pending request on the given
// (pid, fd) and removes them from the queue. Called when the socket closes.
//
// This only ever targets the fd-keyed identity space — close is a syscall-
// level event and always carries a real fd, but an SSLFallback request was
// deliberately never filed under one (#171: guessing a fd is rejected as a
// cross-pairing risk). So Close can never evict an SSLFallback-pending
// request, even when the underlying socket for its SSL* did close; Sweep's
// timeout eviction is the only path that reclaims those.
func (p *Pairer) Close(pid uint32, fd int32, closeTsNs uint64) []PairedEvent {
	key := keyFor(pid, fd, 0, false)
	msgs := p.pending[key]
	if len(msgs) == 0 {
		return nil
	}
	out := make([]PairedEvent, len(msgs))
	for i, tm := range msgs {
		out[i] = abandonedEvent(tm.msg, AbandonReasonClosed,
			time.Duration(int64(closeTsNs)-int64(tm.msg.TsNs)))
	}
	delete(p.pending, key)
	return out
}

// Sweep evicts any pending request older than timeout and returns abandoned
// PairedEvents for each. Called periodically to catch hard-crash cases where
// the close syscall never fires.
func (p *Pairer) Sweep(timeout time.Duration) []PairedEvent {
	if len(p.pending) == 0 {
		return nil
	}
	now := p.now()
	var out []PairedEvent
	for key, msgs := range p.pending {
		var keep []timedMessage
		for _, tm := range msgs {
			if now.Sub(tm.arrivedAt) >= timeout {
				out = append(out, abandonedEvent(tm.msg, AbandonReasonTimeout, now.Sub(tm.arrivedAt)))
			} else {
				keep = append(keep, tm)
			}
		}
		if len(keep) == 0 {
			delete(p.pending, key)
		} else {
			p.pending[key] = keep
		}
	}
	return out
}

func abandonedEvent(req Message, reason string, latency time.Duration) PairedEvent {
	return PairedEvent{
		ReqTsNs:       req.TsNs,
		Latency:       latency,
		Pid:           req.Pid,
		Fd:            req.Fd,
		Comm:          req.Comm,
		Method:        req.Req.method,
		Path:          req.Req.path,
		ReqVersion:    req.Req.version,
		ReqBytes:      req.ContentLength,
		ReqHeaders:    req.Headers,
		Abandoned:     true,
		AbandonReason: reason,
		SSL:           req.SSL,
		SSLFallback:   req.SSLFallback,
	}
}
