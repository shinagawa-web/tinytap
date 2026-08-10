package http

import "time"

const (
	AbandonReasonClosed  = "peer closed"
	AbandonReasonTimeout = "timed out"
)

type Pairer struct {
	pending       map[pairKey][]timedMessage
	heldResponses []heldResponse
	now           func() time.Time
}

const maxHeldResponses = 256

type heldResponse struct {
	key pairKey
	msg timedMessage
}

type pairKey struct {
	pid         uint32
	fd          int32
	ssl         uint64
	sslFallback bool
}

func keyFor(pid uint32, fd int32, ssl uint64, sslFallback bool) pairKey {
	if sslFallback {
		return pairKey{pid: pid, ssl: ssl, sslFallback: true}
	}
	return pairKey{pid: pid, fd: fd}
}

type timedMessage struct {
	msg       Message
	arrivedAt time.Time
}

type PairedEvent struct {
	ReqTsNs          uint64        `json:"reqTsNs"`
	Latency          time.Duration `json:"latencyNs"`
	Pid              uint32        `json:"pid"`
	Fd               int32         `json:"fd"`
	Comm             string        `json:"comm"`
	Method           string        `json:"method"`
	Path             string        `json:"path"`
	ReqVersion       string        `json:"reqVersion"`
	Status           int           `json:"status"`
	Reason           string        `json:"reason"`
	ResVersion       string        `json:"resVersion"`
	ResBytes         int           `json:"resBytes"`
	ReqBytes         int           `json:"reqBytes"`
	ReqHeaders       []Header      `json:"reqHeaders"`
	ResHeaders       []Header      `json:"resHeaders"`
	Abandoned        bool          `json:"abandoned"`
	AbandonReason    string        `json:"abandonReason,omitempty"`
	ReqBody          []byte        `json:"reqBody,omitempty"`
	ReqBodyTruncated bool          `json:"reqBodyTruncated"`
	ResBody          []byte        `json:"resBody,omitempty"`
	ResBodyTruncated bool          `json:"resBodyTruncated"`
	SSL              uint64        `json:"ssl,omitempty"`
	SSLFallback      bool          `json:"sslFallback"`
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

func (p *Pairer) indexOfHeldResponse(key pairKey) int {
	for i, hr := range p.heldResponses {
		if hr.key == key {
			return i
		}
	}
	return -1
}

func (p *Pairer) removeHeldResponseAt(i int) heldResponse {
	hr := p.heldResponses[i]
	last := len(p.heldResponses) - 1
	copy(p.heldResponses[i:], p.heldResponses[i+1:])
	p.heldResponses[last] = heldResponse{}
	p.heldResponses = p.heldResponses[:last]
	return hr
}

func (p *Pairer) holdResponse(key pairKey, e Message) {
	p.heldResponses = append(p.heldResponses, heldResponse{key: key, msg: timedMessage{msg: e, arrivedAt: p.now()}})
	if len(p.heldResponses) > maxHeldResponses {
		p.heldResponses[0] = heldResponse{}
		p.heldResponses = p.heldResponses[1:]
	}
}

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

func bodyBytes(cl int, sample []byte) int {
	if cl != 0 {
		return cl
	}
	return len(sample)
}

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
