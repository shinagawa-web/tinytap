//go:build !amd64 && !arm64

package loader

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/shinagawa-web/tinytap/internal/drops"
)

var (
	ErrSSLUprobeUnsupportedArch = errors.New("SSL uprobe is amd64/arm64-only (see #156)")
	ErrSSLRegistryClosed        = errors.New("SSL registry is closed")
)

type SSLObjectsKey struct{ dev, ino uint64 }

type SSLObjects struct{}

func (o *SSLObjects) Lookup(pid uint32, ssl uint64) (int32, bool) { return 0, false }

func (o *SSLObjects) Delete(pid uint32, ssl uint64) {}

func (o *SSLObjects) DeletePids(dead map[uint32]bool) int { return 0 }

func (o *SSLObjects) DropCounts() drops.Counts { return drops.Counts{} }

func (o *SSLObjects) Close() error { return nil }

type SSLLinks struct{}

func (l *SSLLinks) Close() error { return nil }

type SSLRegistry struct{}

func NewSSLRegistry() *SSLRegistry { return &SSLRegistry{} }

func (r *SSLRegistry) Shared(libsslPath string) (*SSLObjects, bool, error) {
	return nil, false, fmt.Errorf("%s: %w (GOARCH=%s)", libsslPath, ErrSSLUprobeUnsupportedArch, runtime.GOARCH)
}

func (r *SSLRegistry) Close() error { return nil }

func AttachSSLSetFd(obj *SSLObjects, pid uint32, libsslPath string) (*SSLLinks, error) {
	return nil, fmt.Errorf("pid %d: %w (GOARCH=%s)", pid, ErrSSLUprobeUnsupportedArch, runtime.GOARCH)
}

func AttachSSLReadWrite(obj *SSLObjects, pid uint32, libsslPath string) (*SSLLinks, error) {
	return nil, fmt.Errorf("pid %d: %w (GOARCH=%s)", pid, ErrSSLUprobeUnsupportedArch, runtime.GOARCH)
}
