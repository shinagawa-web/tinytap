package loader

import (
	"errors"
	"io"
	"testing"
)

type stubCloser struct{ err error }

func (s *stubCloser) Close() error { return s.err }

func TestCloseAllSucceed(t *testing.T) {
	tt := &Tinytap{
		tracepoints: []io.Closer{&stubCloser{}, &stubCloser{}},
	}
	if err := tt.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

func TestCloseOneTracepointError(t *testing.T) {
	sentinel := errors.New("tp fail")
	tt := &Tinytap{
		tracepoints: []io.Closer{&stubCloser{err: sentinel}},
	}
	err := tt.Close()
	if !errors.Is(err, sentinel) {
		t.Errorf("Close() = %v, want to wrap %v", err, sentinel)
	}
}

func TestCloseMultipleErrors(t *testing.T) {
	e1, e2 := errors.New("err1"), errors.New("err2")
	tt := &Tinytap{
		tracepoints: []io.Closer{
			&stubCloser{err: e1},
			&stubCloser{err: e2},
		},
	}
	err := tt.Close()
	if !errors.Is(err, e1) || !errors.Is(err, e2) {
		t.Errorf("Close() = %v, want joined e1 and e2", err)
	}
}

func TestCloseNilReader(t *testing.T) {
	tt := &Tinytap{
		tracepoints: []io.Closer{&stubCloser{}},
	}
	if err := tt.Close(); err != nil {
		t.Errorf("Close with nil Reader = %v, want nil", err)
	}
}
