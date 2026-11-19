//go:build privileged

package loader_test

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/shinagawa-web/tinytap/internal/loader"
)

// TestAttachSSLSetFd_SecondPidAfterFirstExits is the regression test for the
// design flaw sharing BPF objects across pids exposes: tls.Find always
// returns a pid-namespaced path of the form /proc/<pid>/root/<mapped path>,
// which stops resolving the moment that pid exits. If AttachSSLSetFd cached
// a *link.Executable keyed only by (dev, inode) — as internal/loader used to
// (#326) — pid B's attach against an already-shared SSLObjects would reuse
// pid A's now-dead path and fail with ENOENT, breaking the very sharing
// this refactor exists to enable (#327), especially under the short-lived
// process churn that motivated it. AttachSSLSetFd/AttachSSLReadWrite must
// instead resolve the uprobe symbol address once per libssl inode (cached
// on SSLObjects) but always open a *fresh* *link.Executable against the
// calling pid's own live path.
func TestAttachSSLSetFd_SecondPidAfterFirstExits(t *testing.T) {
	libsslPath := findLibSSL(t)

	info, err := os.Stat(libsslPath)
	if err != nil {
		t.Fatalf("stat %s: %v", libsslPath, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Skipf("%s has no execute bit set; run `sudo chmod +x %s` before this test", libsslPath, libsslPath)
	}

	helperPath := buildSSLSetFdHelper(t, t.TempDir())

	reg := loader.NewSSLRegistry()
	defer func() {
		if err := reg.Close(); err != nil {
			t.Errorf("reg.Close: %v", err)
		}
	}()

	// pid A: attach, then let it exit.
	pidA, sslA, fdA, _ := runSSLSetFdHelperAndAttach(t, helperPath, libsslPath, reg, true)

	// pid B: a distinct process, attached via its own live /proc/<pid>/root
	// path against the SAME shared SSLObjects — pid A's path is no longer
	// resolvable at this point, since its helper has exited.
	pidB, sslB, fdB, _ := runSSLSetFdHelperAndAttach(t, helperPath, libsslPath, reg, true)

	obj, _, err := reg.Shared(libsslPath)
	if err != nil {
		t.Fatalf("Shared (should be a cache hit, no new load): %v", err)
	}

	deadline := time.Now().Add(1 * time.Second)
	var gotA, gotB int32
	var okA, okB bool
	for time.Now().Before(deadline) {
		gotA, okA = obj.Lookup(pidA, sslA)
		gotB, okB = obj.Lookup(pidB, sslB)
		if okA && okB {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !okA {
		t.Errorf("Lookup(pidA=%d, sslA=%#x): not found", pidA, sslA)
	} else if gotA != fdA {
		t.Errorf("Lookup(pidA) fd = %d, want %d", gotA, fdA)
	}
	if !okB {
		t.Fatalf("Lookup(pidB=%d, sslB=%#x): not found — pid B's attach against the already-shared object likely failed", pidB, sslB)
	}
	if gotB != fdB {
		t.Errorf("Lookup(pidB) fd = %d, want %d", gotB, fdB)
	}
}

// runSSLSetFdHelperAndAttach starts one ssl_set_fd_helper subprocess,
// attaches SSL_set_fd against the shared registry using the helper's own
// live /proc/<pid>/root-relative libssl path, releases it to make the real
// call, waits for it to finish and exit, and returns its (pid, ssl, fd) plus
// the path it was attached through. If waitExit is true the helper's exit is
// awaited before returning, so its /proc/<pid>/root path is no longer valid
// by the time this function returns — exercising the stale-path regression
// for whichever pid attaches next.
func runSSLSetFdHelperAndAttach(t *testing.T, helperPath, libsslPath string, reg *loader.SSLRegistry, waitExit bool) (pid uint32, ssl uint64, fd int32, procPath string) {
	t.Helper()

	cmd := exec.Command(helperPath, libsslPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	cleanup := func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	if !waitExit {
		t.Cleanup(cleanup)
	}

	reader := bufio.NewReader(stdout)
	readyLine, err := readLineWithTimeout(reader, 5*time.Second)
	if err != nil {
		cleanup()
		t.Fatalf("read READY line: %v", err)
	}

	var sslHex string
	if _, err := fmt.Sscanf(readyLine, "READY %s %d", &sslHex, &fd); err != nil {
		cleanup()
		t.Fatalf("parse READY line %q: %v", readyLine, err)
	}
	ssl, err = strconv.ParseUint(sslHex, 0, 64)
	if err != nil {
		cleanup()
		t.Fatalf("parse ssl pointer %q: %v", sslHex, err)
	}

	pid = uint32(cmd.Process.Pid)
	procPath = fmt.Sprintf("/proc/%d/root%s", pid, libsslPath)

	obj, _, err := reg.Shared(procPath)
	if err != nil {
		cleanup()
		t.Fatalf("Shared(%s): %v", procPath, err)
	}
	links, err := loader.AttachSSLSetFd(obj, pid, procPath)
	if err != nil {
		cleanup()
		t.Fatalf("AttachSSLSetFd(pid=%d, %s): %v", pid, procPath, err)
	}
	t.Cleanup(func() { _ = links.Close() })

	if _, err := io.WriteString(stdin, "\n"); err != nil {
		cleanup()
		t.Fatalf("release helper: %v", err)
	}
	if _, err := readLineWithTimeout(reader, 5*time.Second); err != nil {
		cleanup()
		t.Fatalf("read DONE line: %v", err)
	}
	_ = stdin.Close()

	if waitExit {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("wait for helper exit: %v", err)
		}
		// Confirm the pid-namespaced path is actually gone now, so this test
		// is exercising the real regression rather than a no-op.
		if _, err := os.Stat(procPath); err == nil {
			t.Fatalf("expected %s to be gone after the helper exited", procPath)
		}
	}

	return pid, ssl, fd, procPath
}
