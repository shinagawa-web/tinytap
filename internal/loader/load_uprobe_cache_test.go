//go:build amd64 || arm64

package loader

import (
	"errors"
	"os"
	"sync"
	"testing"
)

// anyExecutablePath returns a path that passes checkLibSSLExecutable (exists,
// executable) but is not a real libssl — Shared still fails on it, either at
// symbol resolution or (if by chance it does resolve, e.g. under an odd test
// binary) it just isn't reached because these tests only assert on the
// error/caching/closed behavior, never on a successful load, which requires
// real BPF privileges and belongs in the privileged integration tests.
func anyExecutablePath(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skip("/proc/self/exe not available")
	}
	return "/proc/self/exe"
}

// TestSSLRegistryShared_NonExistentPathReturnsError verifies a missing file
// produces an error and, critically, does not get cached — a later call with
// the same (bad) path is expected to fail again rather than replay a cached
// error forever.
func TestSSLRegistryShared_NonExistentPathReturnsError(t *testing.T) {
	reg := NewSSLRegistry()
	defer func() { _ = reg.Close() }()

	if _, _, err := reg.Shared("/nonexistent/libssl.so.999"); err == nil {
		t.Error("expected error for non-existent path, got nil")
	}
	reg.mu.Lock()
	n := len(reg.sets)
	reg.mu.Unlock()
	if n != 0 {
		t.Errorf("sets has %d entries after a failed load, want 0", n)
	}
}

// TestSSLRegistryShared_MissingRequiredSymbolDoesNotCache verifies that a
// real, executable file which is not a libssl (missing the required SSL_*
// symbols) fails without ever reaching BPF loading and without being cached.
func TestSSLRegistryShared_MissingRequiredSymbolDoesNotCache(t *testing.T) {
	path := anyExecutablePath(t)

	reg := NewSSLRegistry()
	defer func() { _ = reg.Close() }()

	if _, created, err := reg.Shared(path); err == nil || created {
		t.Errorf("Shared(%s) = created %v, err %v; want an error and created=false", path, created, err)
	}
	reg.mu.Lock()
	n := len(reg.sets)
	reg.mu.Unlock()
	if n != 0 {
		t.Errorf("sets has %d entries after a failed load, want 0", n)
	}
}

// TestSSLRegistryShared_ConcurrentFailedCallsAreSafe drives many concurrent
// Shared calls against a file that cannot succeed and verifies none of them
// leaves a partial cache entry behind — a basic race/safety check on the
// locking in Shared, independent of whether the load itself can succeed
// without BPF privileges.
func TestSSLRegistryShared_ConcurrentFailedCallsAreSafe(t *testing.T) {
	path := anyExecutablePath(t)

	reg := NewSSLRegistry()
	defer func() { _ = reg.Close() }()

	const n = 16
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = reg.Shared(path)
		}()
	}
	wg.Wait()

	reg.mu.Lock()
	got := len(reg.sets)
	reg.mu.Unlock()
	if got != 0 {
		t.Errorf("sets has %d entries after concurrent failed loads, want 0", got)
	}
}

// TestSSLRegistryShared_ClosedReturnsError verifies Shared refuses to load
// (or return) anything once the registry has been closed.
func TestSSLRegistryShared_ClosedReturnsError(t *testing.T) {
	path := anyExecutablePath(t)

	reg := NewSSLRegistry()
	if err := reg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, _, err := reg.Shared(path); !errors.Is(err, ErrSSLRegistryClosed) {
		t.Errorf("Shared after Close: err = %v, want ErrSSLRegistryClosed", err)
	}
}
