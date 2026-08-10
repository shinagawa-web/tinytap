//go:build !amd64 && !arm64

package loader

import (
	"errors"
	"fmt"
	"runtime"
)

var ErrSSLUprobeUnsupportedArch = errors.New("SSL uprobe is amd64/arm64-only (see #156)")

type SSLFdProbe struct{}

func AttachSSLSetFd(pid uint32, libsslPath string) (*SSLFdProbe, error) {
	return nil, fmt.Errorf("pid %d: %w (GOARCH=%s)", pid, ErrSSLUprobeUnsupportedArch, runtime.GOARCH)
}

func (p *SSLFdProbe) Lookup(pid uint32, ssl uint64) (int32, bool) { return 0, false }

func (p *SSLFdProbe) Close() error { return nil }

type SSLPayloadProbe struct{}

func AttachSSLReadWrite(pid uint32, libsslPath string) (*SSLPayloadProbe, error) {
	return nil, fmt.Errorf("pid %d: %w (GOARCH=%s)", pid, ErrSSLUprobeUnsupportedArch, runtime.GOARCH)
}

func (p *SSLPayloadProbe) Close() error { return nil }
