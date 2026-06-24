package main

import (
	"io"

	"github.com/shinagawa-web/tinytap/internal/loader"
)

// tinytapSession implements bpfSession using a separate reader and closer so
// neither field carries an eBPF dependency and the struct can be tested with
// plain fakes.
type tinytapSession struct {
	rd     ringbufCloser
	closer io.Closer
}

func (s *tinytapSession) reader() ringbufCloser { return s.rd }
func (s *tinytapSession) Close() error          { return s.closer.Close() }

// loaderLoad is the real loader.Load; tests can replace it with a fake.
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
