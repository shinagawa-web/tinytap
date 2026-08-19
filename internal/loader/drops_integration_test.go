//go:build privileged

package loader

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
	"golang.org/x/sys/unix"
)

func TestLoaderDropCounts_RingbufReserveFailure(t *testing.T) {
	tt, err := Load(0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer tt.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	const maxWrites = 6000
	buf := []byte("x")
	for i := 0; i < maxWrites; i++ {
		if _, err := w.Write(buf); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if tt.DropCounts().Ringbuf > 0 {
			return
		}
	}
	t.Fatalf("Ringbuf drop count still 0 after %d writes with nothing draining the ring", maxWrites)
}

func TestLoaderDropCounts_MapFullFailure(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	realTid := uint32(syscall.Gettid())

	tt, err := Load(0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer tt.Close()

	const (
		maxEntries = 10240
		keyBase    = 1_000_000_000
	)
	// The map is shared with every process on the machine (stash_incoming
	// hooks read/recvfrom/recvmsg/readv/sendfile at syscall entry for
	// everyone except our own pid), so an unrelated in-flight syscall can
	// occupy a slot and make the map fill up (E2BIG) before this loop
	// reaches maxEntries. That's still the "map full" state this test
	// wants, so treat E2BIG here as reaching it early rather than a fatal
	// test-infra error (#331); any other error is a genuine failure.
	var val bpf.TinytapIncomingPending
	for i := uint32(0); i < maxEntries; i++ {
		key := keyBase + i
		if key == realTid {
			t.Fatalf("synthetic key %d unexpectedly collided with the real tid", key)
		}
		if err := tt.objs.IncomingPendingMap.Put(&key, &val); err != nil {
			if errors.Is(err, unix.E2BIG) {
				break
			}
			t.Fatalf("prefill map at key %d: %v", key, err)
		}
	}
	defer func() {
		for i := uint32(0); i < maxEntries; i++ {
			key := keyBase + i
			_ = tt.objs.IncomingPendingMap.Delete(&key)
		}
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1)
	if _, err := r.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if got := tt.DropCounts().MapFull; got == 0 {
		t.Fatalf("MapFull drop count = 0, want > 0 after triggering stash_incoming against a full map")
	}
}
