//go:build !arm64

package loader_test

import (
	"errors"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/loader"
)

func TestAttachSSLSetFd_UnsupportedArch(t *testing.T) {
	probe, err := loader.AttachSSLSetFd(123, "/lib/libssl.so.3")
	if probe != nil {
		t.Errorf("AttachSSLSetFd probe = %v, want nil", probe)
	}
	if !errors.Is(err, loader.ErrSSLSetFdUnsupportedArch) {
		t.Errorf("AttachSSLSetFd err = %v, want wrapping ErrSSLSetFdUnsupportedArch", err)
	}
}

func TestSSLFdProbeStub_LookupAndClose(t *testing.T) {
	var p *loader.SSLFdProbe

	if fd, ok := p.Lookup(123, 0xdeadbeef); ok || fd != 0 {
		t.Errorf("Lookup = %d, %v; want 0, false", fd, ok)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}
