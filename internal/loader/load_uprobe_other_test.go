//go:build !amd64 && !arm64

package loader_test

import (
	"errors"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/drops"
	"github.com/shinagawa-web/tinytap/internal/loader"
)

func TestSSLRegistryShared_UnsupportedArch(t *testing.T) {
	reg := loader.NewSSLRegistry()
	obj, created, err := reg.Shared("/lib/libssl.so.3")
	if obj != nil {
		t.Errorf("Shared obj = %v, want nil", obj)
	}
	if created {
		t.Error("Shared created = true, want false")
	}
	if !errors.Is(err, loader.ErrSSLUprobeUnsupportedArch) {
		t.Errorf("Shared err = %v, want wrapping ErrSSLUprobeUnsupportedArch", err)
	}
	if err := reg.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

func TestSSLObjectsStub_LookupAndClose(t *testing.T) {
	var o *loader.SSLObjects

	if fd, ok := o.Lookup(123, 0xdeadbeef); ok || fd != 0 {
		t.Errorf("Lookup = %d, %v; want 0, false", fd, ok)
	}
	o.Delete(123, 0xdeadbeef)
	if n := o.DeletePids(map[uint32]bool{123: true}); n != 0 {
		t.Errorf("DeletePids() = %d, want 0", n)
	}
	if got := o.DropCounts(); got != (drops.Counts{}) {
		t.Errorf("DropCounts() = %+v, want zero value", got)
	}
	if err := o.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

func TestAttachSSLSetFd_UnsupportedArch(t *testing.T) {
	links, err := loader.AttachSSLSetFd(nil, 123, "/lib/libssl.so.3")
	if links != nil {
		t.Errorf("AttachSSLSetFd links = %v, want nil", links)
	}
	if !errors.Is(err, loader.ErrSSLUprobeUnsupportedArch) {
		t.Errorf("AttachSSLSetFd err = %v, want wrapping ErrSSLUprobeUnsupportedArch", err)
	}
}

func TestAttachSSLReadWrite_UnsupportedArch(t *testing.T) {
	links, err := loader.AttachSSLReadWrite(nil, 123, "/lib/libssl.so.3")
	if links != nil {
		t.Errorf("AttachSSLReadWrite links = %v, want nil", links)
	}
	if !errors.Is(err, loader.ErrSSLUprobeUnsupportedArch) {
		t.Errorf("AttachSSLReadWrite err = %v, want wrapping ErrSSLUprobeUnsupportedArch", err)
	}
}

func TestSSLLinksStub_Close(t *testing.T) {
	var l *loader.SSLLinks
	if err := l.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}
