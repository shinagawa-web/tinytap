package http

import "time"

const (
	AbandonReasonClosed  = "peer closed"
	AbandonReasonTimeout = "timed out"
)

// Pairer matches HTTP requests with their responses on the same (pid, fd)
// and emits a single PairedEvent at the moment the response's headers
// arrive. Requests with no response yet stay queued; responses without a
// queued request are dropped (likely captured mid-stream).
//
// HTTP/1.1 keep-alive guarantees responses are returned in request order,
// so a simple FIFO per (pid, fd) is sufficient. Chunked encoding and
// HTTP/2 are out of scope for v0.1.0.
type Pairer struct {
	pending map[pidFd][]timedMessage
	now     func() time.Time
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
	ReqTsNs      uint64        // request first-byte timestamp (BPF ktime ns)
	Latency      time.Duration // res.TsNs - req.TsNs, or elapsed wall time for abandoned
	Pid          uint32
	Fd           int32
	Comm         string
	Method       string
	Path         string
	ReqVersion   string // request start-line HTTP version (e.g. "HTTP/1.1")
	Status       int
	Reason       string   // response reason phrase (e.g. "OK", "Not Found")
	ResVersion   string   // response start-line HTTP version
	ResBytes     int      // response body bytes (Content-Length, post-no-body override)
	ReqBytes     int      // request body bytes (Content-Length, post-no-body override)
	ReqHeaders   []Header // request headers in on-wire order
	ResHeaders   []Header // response headers in on-wire order
	Abandoned    bool     // true when the request never received a response
	AbandonReason string  // AbandonReasonClosed or AbandonReasonTimeout
	// Captured body samples (#35). Empty when the message carried no body.
	// *Truncated marks that some body bytes were lost (sample cap or budget).
	ReqBody          []byte
	ReqBodyTruncated bool
	ResBody          []byte
	ResBodyTruncated bool
}

func NewPairer() *Pairer {
	return newPairerWithClock(time.Now)
}

func newPairerWithClock(now func() time.Time) *Pairer {
	return &Pairer{
		pending: make(map[pidFd][]timedMessage),
		now:     now,
	}
}

// Push registers an HTTP event with the pairer. If the event is a request,
// it is queued and nil is returned. If the event is a response and a
// matching request is queued, the request is dequeued and a paired event
// is returned. Unmatched responses (request was missed) yield nil so the
// caller can decide whether to render them on their own.
func (p *Pairer) Push(e Message) (PairedEvent, bool) {
	key := pidFd{pid: e.Pid, fd: e.Fd}
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
		ResBytes:   e.ContentLength,
		ReqBytes:   req.ContentLength,
		ReqHeaders: req.Headers,
		ResHeaders: e.Headers,

		ReqBody:          req.BodySample,
		ReqBodyTruncated: req.BodyTruncated,
		ResBody:          e.BodySample,
		ResBodyTruncated: e.BodyTruncated,
	}, true
}

// Close emits an abandoned PairedEvent for every pending request on the given
// (pid, fd) and removes them from the queue. Called when the socket closes.
func (p *Pairer) Close(pid uint32, fd int32, closeTsNs uint64) []PairedEvent {
	key := pidFd{pid: pid, fd: fd}
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
	}
}
