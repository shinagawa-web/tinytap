package http

import "time"

const (
	AbandonReasonClosed  = "peer closed"
	AbandonReasonTimeout = "timed out"
)

// Pairer matches HTTP requests with their responses on the same connection
// identity and emits a single PairedEvent once both sides are known. In the
// common case that's the moment the response's headers arrive, with the
// request already queued. Requests with no response yet stay queued.
//
// A response with no queued request (#67 — an early error response, e.g.
// 413/417, or a 100-continue reply, arriving while the client is still
// streaming its request body) is held rather than dropped, and the
// PairedEvent is instead emitted once the matching request is later pushed.
// heldResponses is bounded
// (maxHeldResponses, oldest dropped first) so a response whose request was
// never captured at all — a stream joined mid-flight — cannot accumulate
// unbounded; that bound is the reason unmatched responses were dropped in
// the first place.
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
// two unrelated exchanges. CloseSSL (#173) is the SSL*-keyed counterpart to
// Close, driven by the SSL_free uprobe instead of the close(2) syscall.
type Pairer struct {
	pending       map[pairKey][]timedMessage
	heldResponses []heldResponse
	now           func() time.Time
}

// maxHeldResponses bounds heldResponses across all keys combined (not
// per-key): the number of distinct (pid, fd)/(pid, ssl) identities is itself
// unbounded, so a per-key cap alone would not bound total memory. Chosen
// generously relative to how rare an early/out-of-order response actually is
// in practice — this is a safety net against a genuinely orphaned stream,
// not a path exercised under normal traffic.
const maxHeldResponses = 256

// heldResponse is a response Push could not immediately pair, kept in
// arrival order (oldest first) so a same-key request can claim the oldest
// match, and so exceeding maxHeldResponses always evicts the oldest response
// overall.
type heldResponse struct {
	key pairKey
	msg timedMessage
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

// Push registers an HTTP event with the pairer. If the event is a request
// and a held response (#67) is already waiting on the same identity, they
// pair immediately; otherwise the request is queued. If the event is a
// response and a matching request is queued, the request is dequeued and a
// paired event is returned; otherwise the response is held (see
// heldResponses) so a later request can still claim it.
//
// A request and its response only pair when they carry the *same* identity
// kind: an SSLFallback request never pairs with an ordinary fd-keyed
// response even if their Pid/Fd/SSL values happened to coincide, and vice
// versa — keyFor's discriminator makes that impossible by construction.
//
// A malformed SSLFallback message (SSL == 0 — no producer should ever emit
// one, but Push does not trust that) is dropped rather than paired or held:
// keying it on (pid, ssl=0) would collapse every SSL* this pid ever fails to
// set onto one shared FIFO, reopening exactly the cross-pairing risk #171
// exists to close, just from a different bug than a guessed fd.
func (p *Pairer) Push(e Message) (PairedEvent, bool) {
	if e.SSLFallback && e.SSL == 0 {
		return PairedEvent{}, false
	}
	key := keyFor(e.Pid, e.Fd, e.SSL, e.SSLFallback)
	if e.IsRequest {
		if i := p.indexOfHeldResponse(key); i != -1 {
			res := p.removeHeldResponseAt(i)
			return pairRequestResponse(e, res.msg.msg), true
		}
		p.pending[key] = append(p.pending[key], timedMessage{msg: e, arrivedAt: p.now()})
		return PairedEvent{}, false
	}
	q := p.pending[key]
	if len(q) == 0 {
		p.holdResponse(key, e)
		return PairedEvent{}, false
	}
	req := q[0].msg
	if len(q) == 1 {
		delete(p.pending, key)
	} else {
		p.pending[key] = q[1:]
	}
	return pairRequestResponse(req, e), true
}

// indexOfHeldResponse returns the index of the oldest held response on key,
// or -1 if none is held.
func (p *Pairer) indexOfHeldResponse(key pairKey) int {
	for i, hr := range p.heldResponses {
		if hr.key == key {
			return i
		}
	}
	return -1
}

// removeHeldResponseAt removes and returns the held response at index i. It
// zeroes the vacated backing-array slot before shrinking the slice — a plain
// append(s[:i], s[i+1:]...) would leave a duplicate reference to the last
// surviving element sitting in that now-out-of-range slot, keeping its
// Message (and captured BodySample/Headers) reachable until some later
// append happens to overwrite it.
func (p *Pairer) removeHeldResponseAt(i int) heldResponse {
	hr := p.heldResponses[i]
	last := len(p.heldResponses) - 1
	copy(p.heldResponses[i:], p.heldResponses[i+1:])
	p.heldResponses[last] = heldResponse{}
	p.heldResponses = p.heldResponses[:last]
	return hr
}

// holdResponse records a response that arrived with no queued request,
// evicting the globally oldest held response first if that would exceed
// maxHeldResponses. The evicted slot is zeroed before reslicing, for the
// same reason removeHeldResponseAt zeroes its vacated slot.
func (p *Pairer) holdResponse(key pairKey, e Message) {
	p.heldResponses = append(p.heldResponses, heldResponse{key: key, msg: timedMessage{msg: e, arrivedAt: p.now()}})
	if len(p.heldResponses) > maxHeldResponses {
		p.heldResponses[0] = heldResponse{}
		p.heldResponses = p.heldResponses[1:]
	}
}

// pairRequestResponse builds the PairedEvent for a matched request/response,
// shared by the in-order path (request already queued) and the #67
// out-of-order path (response held, matched once the request arrives).
func pairRequestResponse(req, res Message) PairedEvent {
	return PairedEvent{
		ReqTsNs:    req.TsNs,
		Latency:    time.Duration(int64(res.TsNs) - int64(req.TsNs)),
		Pid:        req.Pid,
		Fd:         req.Fd,
		Comm:       req.Comm,
		Method:     req.Req.method,
		Path:       req.Req.path,
		ReqVersion: req.Req.version,
		Status:     res.Res.status,
		Reason:     res.Res.reason,
		ResVersion: res.Res.version,
		ResBytes:   bodyBytes(res.ContentLength, res.BodySample),
		ReqBytes:   bodyBytes(req.ContentLength, req.BodySample),
		ReqHeaders: req.Headers,
		ResHeaders: res.Headers,

		ReqBody:          req.BodySample,
		ReqBodyTruncated: req.BodyTruncated,
		ResBody:          res.BodySample,
		ResBodyTruncated: res.BodyTruncated,

		SSL:         req.SSL,
		SSLFallback: req.SSLFallback,
	}
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
// request, even when the underlying socket for its SSL* did close; CloseSSL
// (driven by the SSL_free uprobe, #173) is the fd-less counterpart, with
// Sweep's timeout eviction remaining as the fallback for both key spaces
// when neither close signal ever arrives (e.g. a hard crash).
func (p *Pairer) Close(pid uint32, fd int32, closeTsNs uint64) []PairedEvent {
	key := keyFor(pid, fd, 0, false)
	p.discardHeldResponses(key)
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

// CloseSSL emits an abandoned PairedEvent for every pending SSLFallback
// request on the given (pid, ssl) and removes them from the queue. Called
// when the SSL_free uprobe (#173) observes the connection's SSL* object
// being freed — OpenSSL's mandatory, always-called teardown API, fired
// exactly once per SSL object regardless of how its BIO/fd was wired
// (confirmed for curl's custom-BIO path too, see #167). This is the
// fd-less counterpart to Close: it only ever targets the SSL*-keyed
// identity space and can never evict an ordinary fd-keyed request, by the
// same keyFor discriminator Push and Close rely on.
func (p *Pairer) CloseSSL(pid uint32, ssl uint64, closeTsNs uint64) []PairedEvent {
	key := keyFor(pid, 0, ssl, true)
	p.discardHeldResponses(key)
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

// discardHeldResponses drops any held response on key. Called from Close and
// CloseSSL: once a connection tears down, a held response for it can never
// be claimed by a future request, and — critically — fd numbers get reused,
// so leaving it in place risks a later, unrelated connection on the same
// (pid, fd) wrongly claiming it (see TestPairerCloseDiscardsHeldResponse).
//
// The in-place filter below can leave a discarded entry's Message reachable
// in the tail of the backing array (beyond the filtered slice's new
// length) — the tail slots get explicitly zeroed after filtering so a
// discarded response's BodySample/Headers don't outlive the discard.
func (p *Pairer) discardHeldResponses(key pairKey) {
	if len(p.heldResponses) == 0 {
		return
	}
	orig := len(p.heldResponses)
	kept := p.heldResponses[:0]
	for _, hr := range p.heldResponses {
		if hr.key != key {
			kept = append(kept, hr)
		}
	}
	for i := len(kept); i < orig; i++ {
		p.heldResponses[i] = heldResponse{}
	}
	p.heldResponses = kept
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
