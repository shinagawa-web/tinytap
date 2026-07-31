//go:build !amd64 && !arm64

package loader

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrSSLUprobeUnsupportedArch is returned by AttachSSLSetFd and
// AttachSSLReadWrite on every GOARCH other than amd64 and arm64. The SSL
// uprobes (#147/#146) need a real,
// arch-correct struct pt_regs for their PT_REGS_PARMn argument macros; only
// those two arches supply one (arm64 via the vendored vmlinux.h, x86_64 via
// the hand-declared bpf/pt_regs_x86_64.h — see bpf/gen.go and #156), so the
// bpf2go bindings are not built for any other GOARCH.
var ErrSSLUprobeUnsupportedArch = errors.New("SSL uprobe is amd64/arm64-only (see #156)")

// SSLFdProbe is a no-op stand-in on unsupported arches; AttachSSLSetFd never
// returns one, so its methods are unreachable in practice.
type SSLFdProbe struct{}

// AttachSSLSetFd always fails on unsupported arches. See ErrSSLUprobeUnsupportedArch.
func AttachSSLSetFd(pid uint32, libsslPath string) (*SSLFdProbe, error) {
	return nil, fmt.Errorf("pid %d: %w (GOARCH=%s)", pid, ErrSSLUprobeUnsupportedArch, runtime.GOARCH)
}

// Lookup always reports not found on unsupported arches.
func (p *SSLFdProbe) Lookup(pid uint32, ssl uint64) (int32, bool) { return 0, false }

// Close is a no-op on unsupported arches.
func (p *SSLFdProbe) Close() error { return nil }

// SSLPayloadProbe is a no-op stand-in on unsupported arches; AttachSSLReadWrite
// never returns one, so its methods are unreachable in practice.
type SSLPayloadProbe struct{}

// AttachSSLReadWrite always fails on unsupported arches, for the same reason
// as AttachSSLSetFd. See ErrSSLUprobeUnsupportedArch.
func AttachSSLReadWrite(pid uint32, libsslPath string) (*SSLPayloadProbe, error) {
	return nil, fmt.Errorf("pid %d: %w (GOARCH=%s)", pid, ErrSSLUprobeUnsupportedArch, runtime.GOARCH)
}

// Close is a no-op on unsupported arches.
func (p *SSLPayloadProbe) Close() error { return nil }
