package http

import "time"

// Pairer matches HTTP requests with their responses on the same (pid, fd)
// and emits a single PairedEvent at the moment the response's headers
// arrive. Requests with no response yet stay queued; responses without a
// queued request are dropped (likely captured mid-stream).
//
// HTTP/1.1 keep-alive guarantees responses are returned in request order,
// so a simple FIFO per (pid, fd) is sufficient. Chunked encoding and
// HTTP/2 are out of scope for v0.1.0.
type Pairer struct {
	pending map[pidFd][]Message
}

// PairedEvent is what the pairer hands off to the renderer once a request
// and response have been matched on the same (pid, fd). It carries every
// HTTP-level field the parser surfaced — even ones the default render
// line doesn't print — so future detail views (TUI row-expand, structured
// export) don't need to reach back into the parser layer.
type PairedEvent struct {
	ReqTsNs    uint64        // request first-byte timestamp (BPF ktime ns)
	Latency    time.Duration // res.TsNs - req.TsNs
	Pid        uint32
	Fd         int32
	Comm       string
	Method     string
	Path       string
	ReqVersion string // request start-line HTTP version (e.g. "HTTP/1.1")
	Status     int
	Reason     string // response reason phrase (e.g. "OK", "Not Found")
	ResVersion string // response start-line HTTP version
	ResBytes   int    // response body bytes (Content-Length, post-no-body override)
}

func NewPairer() *Pairer {
	return &Pairer{pending: make(map[pidFd][]Message)}
}

// Push registers an HTTP event with the pairer. If the event is a request,
// it is queued and nil is returned. If the event is a response and a
// matching request is queued, the request is dequeued and a paired event
// is returned. Unmatched responses (request was missed) yield nil so the
// caller can decide whether to render them on their own.
func (p *Pairer) Push(e Message) (PairedEvent, bool) {
	key := pidFd{pid: e.Pid, fd: e.Fd}
	if e.IsRequest {
		p.pending[key] = append(p.pending[key], e)
		return PairedEvent{}, false
	}
	q := p.pending[key]
	if len(q) == 0 {
		return PairedEvent{}, false
	}
	req := q[0]
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
	}, true
}

// Close drops any pending requests on the given (pid, fd). Called when
// the socket is closed; those requests will never see a response.
func (p *Pairer) Close(pid uint32, fd int32) {
	delete(p.pending, pidFd{pid: pid, fd: fd})
}
