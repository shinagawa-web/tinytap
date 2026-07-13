//go:build privileged

package loader_test

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shinagawa-web/tinytap/internal/loader"
)

// findLibSSL resolves the system's libssl.so.3 path via ldconfig, the same
// way a real caller would (internal/tls.Find scans /proc/<pid>/maps, but
// for this test we just need any real libssl on disk).
func findLibSSL(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("ldconfig", "-p").Output()
	if err != nil {
		t.Skipf("ldconfig not available: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "libssl.so.3") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			// Last field is the resolved path, e.g. "=> /lib/aarch64-linux-gnu/libssl.so.3".
			return fields[len(fields)-1]
		}
	}
	t.Skip("libssl.so.3 not found via ldconfig, skipping TLS uprobe test")
	return ""
}

// buildSSLSetFdHelper compiles testdata/ssl_set_fd_helper.c with cc.
func buildSSLSetFdHelper(t *testing.T, dir string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available, skipping uprobe fixture test")
	}
	outPath := dir + "/ssl_set_fd_helper"
	cmd := exec.Command(cc, "-o", outPath, "testdata/ssl_set_fd_helper.c", "-ldl")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile ssl_set_fd_helper: %v\n%s", err, out)
	}
	return outPath
}

// TestAttachSSLSetFd_RealCall drives a real SSL_set_fd(3) call in a
// subprocess against the system's real libssl.so.3 and confirms
// AttachSSLSetFd's map records the correct (pid, ssl) -> fd mapping (#147).
func TestAttachSSLSetFd_RealCall(t *testing.T) {
	libsslPath := findLibSSL(t)

	// AttachSSLSetFd deliberately does not chmod its target (#147 — a
	// capture tool silently mutating a system library's permissions is a
	// surprising side effect). Distro-packaged libssl commonly ships
	// without the execute bit (e.g. Debian/Ubuntu's libssl3 package), so
	// skip with an actionable message rather than failing outright.
	info, err := os.Stat(libsslPath)
	if err != nil {
		t.Fatalf("stat %s: %v", libsslPath, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Skipf("%s has no execute bit set; run `sudo chmod +x %s` before this test", libsslPath, libsslPath)
	}

	helperPath := buildSSLSetFdHelper(t, t.TempDir())

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
	// If a Fatalf below fires before the go-ahead newline is written (e.g. a
	// timeout reading the READY line), the helper would otherwise block
	// forever on fgets(stdin) and hang cmd.Wait(). Closing stdin and killing
	// the process are both best-effort and safe to call after a normal
	// exit too — they just no-op.
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	reader := bufio.NewReader(stdout)
	readyLine, err := readLineWithTimeout(reader, 5*time.Second)
	if err != nil {
		t.Fatalf("read READY line: %v", err)
	}

	var sslHex string
	var fd int32
	if _, err := fmt.Sscanf(readyLine, "READY %s %d", &sslHex, &fd); err != nil {
		t.Fatalf("parse READY line %q: %v", readyLine, err)
	}
	ssl, err := strconv.ParseUint(sslHex, 0, 64)
	if err != nil {
		t.Fatalf("parse ssl pointer %q: %v", sslHex, err)
	}

	pid := uint32(cmd.Process.Pid)
	probe, err := loader.AttachSSLSetFd(pid, libsslPath)
	if err != nil {
		t.Fatalf("AttachSSLSetFd: %v", err)
	}
	defer func() {
		if err := probe.Close(); err != nil {
			t.Errorf("probe.Close: %v", err)
		}
	}()

	if _, err := io.WriteString(stdin, "\n"); err != nil {
		t.Fatalf("release helper: %v", err)
	}

	if _, err := readLineWithTimeout(reader, 5*time.Second); err != nil {
		t.Fatalf("read DONE line: %v", err)
	}

	deadline := time.Now().Add(1 * time.Second)
	var gotFD int32
	var ok bool
	for time.Now().Before(deadline) {
		gotFD, ok = probe.Lookup(pid, ssl)
		if ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("Lookup(pid=%d, ssl=%#x): not found", pid, ssl)
	}
	if gotFD != fd {
		t.Errorf("Lookup(pid=%d, ssl=%#x) fd = %d, want %d", pid, ssl, gotFD, fd)
	}
}

func readLineWithTimeout(r *bufio.Reader, timeout time.Duration) (string, error) {
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- result{strings.TrimSpace(line), err}
	}()
	select {
	case res := <-ch:
		return res.line, res.err
	case <-time.After(timeout):
		return "", fmt.Errorf("timed out after %s", timeout)
	}
}
