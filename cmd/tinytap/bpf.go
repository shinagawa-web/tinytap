package main

import (
	"github.com/shinagawa-web/tinytap/internal/loader"
)

// tinytapSession wraps *loader.Tinytap to satisfy bpfSession.
type tinytapSession struct{ tt *loader.Tinytap }

func (s *tinytapSession) reader() ringbufCloser { return s.tt.Reader }
func (s *tinytapSession) Close() error          { return s.tt.Close() }

func init() {
	loadBPF = func(pid uint32) (bpfSession, error) {
		tt, err := loader.Load(pid)
		if err != nil {
			return nil, err
		}
		return &tinytapSession{tt}, nil
	}
}
