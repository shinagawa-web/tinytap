//go:build !arm64

package loader

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrSSLSetFdUnsupportedArch is returned by AttachSSLSetFd on every GOARCH
// other than arm64. The SSL_set_fd uprobe (#147) needs a real
// kernel-internal struct pt_regs for its PT_REGS_PARMn argument macros,
// only available from a BTF-derived vmlinux.h — this repo's vendored one
// reflects only the arm64 dev VM it was generated on. x86_64 support is
// tracked in #156.
var ErrSSLSetFdUnsupportedArch = errors.New("SSL_set_fd uprobe is arm64-only for now (see #156)")

// SSLFdProbe is a no-op stand-in on non-arm64 arches; AttachSSLSetFd never
// returns one, so its methods are unreachable in practice.
type SSLFdProbe struct{}

// AttachSSLSetFd always fails on non-arm64 arches. See ErrSSLSetFdUnsupportedArch.
func AttachSSLSetFd(pid uint32, libsslPath string) (*SSLFdProbe, error) {
	return nil, fmt.Errorf("pid %d: %w (GOARCH=%s)", pid, ErrSSLSetFdUnsupportedArch, runtime.GOARCH)
}

// Lookup always reports not found on non-arm64 arches.
func (p *SSLFdProbe) Lookup(pid uint32, ssl uint64) (int32, bool) { return 0, false }

// Close is a no-op on non-arm64 arches.
func (p *SSLFdProbe) Close() error { return nil }
