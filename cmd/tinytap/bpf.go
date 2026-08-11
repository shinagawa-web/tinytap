package main

import (
	"io"

	"github.com/shinagawa-web/tinytap/internal/drops"
	"github.com/shinagawa-web/tinytap/internal/loader"
)

type tinytapSession struct {
	rd     ringbufCloser
	closer io.Closer
	drops  func() drops.Counts
}

func (s *tinytapSession) reader() ringbufCloser { return s.rd }
func (s *tinytapSession) Close() error          { return s.closer.Close() }

// drops is nil for sessions built without a loader object (tests, and any
// future caller that doesn't need counters), so report zero rather than panic.
func (s *tinytapSession) dropCounts() drops.Counts {
	if s.drops == nil {
		return drops.Counts{}
	}
	return s.drops()
}

var loaderLoad = loader.Load

func init() {
	loadBPF = func(pid uint32) (bpfSession, error) {
		tt, err := loaderLoad(pid)
		if err != nil {
			return nil, err
		}
		return &tinytapSession{rd: tt.Reader, closer: tt, drops: tt.DropCounts}, nil
	}
}
