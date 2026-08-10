package main

import (
	"io"

	"github.com/shinagawa-web/tinytap/internal/loader"
)

type tinytapSession struct {
	rd     ringbufCloser
	closer io.Closer
}

func (s *tinytapSession) reader() ringbufCloser { return s.rd }
func (s *tinytapSession) Close() error          { return s.closer.Close() }

var loaderLoad = loader.Load

func init() {
	loadBPF = func(pid uint32) (bpfSession, error) {
		tt, err := loaderLoad(pid)
		if err != nil {
			return nil, err
		}
		return &tinytapSession{rd: tt.Reader, closer: tt}, nil
	}
}
