//go:build amd64 || arm64

package loader

import (
	"os"
	"sync"
	"testing"

	"github.com/cilium/ebpf/link"
)

// clearExeCache empties the package-level ELF executable cache.
// Call at the start of each test that exercises openExecutable so that
// prior test runs do not leak cached entries.
func clearExeCache() {
	exCache.Range(func(k, v any) bool {
		exCache.Delete(k)
		return true
	})
}

func TestOpenExecutable_SameFileReturnsCachedPointer(t *testing.T) {
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skip("/proc/self/exe not available")
	}
	clearExeCache()

	a, err := openExecutable("/proc/self/exe")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b, err := openExecutable("/proc/self/exe")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if a != b {
		t.Errorf("expected same *link.Executable pointer on second call, got different pointers")
	}
}

func TestOpenExecutable_NonExistentPathReturnsError(t *testing.T) {
	clearExeCache()
	_, err := openExecutable("/nonexistent/libssl.so.999")
	if err == nil {
		t.Error("expected error for non-existent path, got nil")
	}
}

func TestOpenExecutable_ConcurrentCallsReturnSamePointer(t *testing.T) {
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skip("/proc/self/exe not available")
	}
	clearExeCache()

	const n = 16
	results := make([]*link.Executable, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ex, err := openExecutable("/proc/self/exe")
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			results[i] = ex
		}()
	}
	wg.Wait()

	first := results[0]
	for i, ex := range results {
		if ex != nil && ex != first {
			t.Errorf("results[%d] is a different *link.Executable than results[0]", i)
		}
	}
}
