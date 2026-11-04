//go:build privileged

package loader

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

// findLibSSLForSSLFdMapTest and buildSSLSetFdHelperForSSLFdMapTest duplicate
// uprobe_integration_test.go's findLibSSL/buildSSLSetFdHelper — those live in
// the external loader_test package, and this test needs direct access to
// SSLFdProbe's unexported objs field to prefill ssl_fd_map, so it must be an
// internal (package loader) test instead.
func findLibSSLForSSLFdMapTest(t *testing.T) string {
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
			return fields[len(fields)-1]
		}
	}
	t.Skip("libssl.so.3 not found via ldconfig, skipping TLS uprobe drops test")
	return ""
}

func buildSSLSetFdHelperForSSLFdMapTest(t *testing.T, dir string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available, skipping uprobe drops test")
	}
	outPath := dir + "/ssl_set_fd_helper"
	cmd := exec.Command(cc, "-o", outPath, "testdata/ssl_set_fd_helper.c", "-ldl")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile ssl_set_fd_helper: %v\n%s", err, out)
	}
	return outPath
}

func readSSLFdMapTestLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
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
		if res.err != nil {
			t.Fatalf("read line: %v", res.err)
		}
		return res.line
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading line")
		return ""
	}
}

// TestSSLFdProbeDropCounts_MapFullFailure prefills ssl_fd_map to its
// 10240-entry cap with synthetic keys, then drives one real SSL_set_fd(3)
// call in a subprocess — a genuinely new key against a full map — and
// confirms the resulting E2BIG is counted rather than silently dropped
// (#290). ssl_fd_map has no delete path (#297), so this is the map most
// likely to actually fill in production.
func TestSSLFdProbeDropCounts_MapFullFailure(t *testing.T) {
	libsslPath := findLibSSLForSSLFdMapTest(t)

	info, err := os.Stat(libsslPath)
	if err != nil {
		t.Fatalf("stat %s: %v", libsslPath, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Skipf("%s has no execute bit set; run `sudo chmod +x %s` before this test", libsslPath, libsslPath)
	}

	helperPath := buildSSLSetFdHelperForSSLFdMapTest(t, t.TempDir())

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
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	reader := bufio.NewReader(stdout)
	readyLine := readSSLFdMapTestLine(t, reader)

	var sslHex string
	var fd int32
	if _, err := fmt.Sscanf(readyLine, "READY %s %d", &sslHex, &fd); err != nil {
		t.Fatalf("parse READY line %q: %v", readyLine, err)
	}

	pid := uint32(cmd.Process.Pid)

	reg := NewSSLRegistry()
	defer func() {
		if err := reg.Close(); err != nil {
			t.Errorf("reg.Close: %v", err)
		}
	}()
	obj, _, err := reg.Shared(libsslPath)
	if err != nil {
		t.Fatalf("Shared: %v", err)
	}
	links, err := AttachSSLSetFd(obj, pid, libsslPath)
	if err != nil {
		t.Fatalf("AttachSSLSetFd: %v", err)
	}
	defer func() {
		if err := links.Close(); err != nil {
			t.Errorf("links.Close: %v", err)
		}
	}()

	const (
		maxEntries = 10240
		keyBase    = 1_000_000_000
	)
	var val int32
	for i := uint32(0); i < maxEntries; i++ {
		key := bpf.TinytapUprobeSslFdKey{Pid: keyBase + i}
		if key.Pid == pid {
			t.Fatalf("synthetic pid %d unexpectedly collided with the helper's real pid", key.Pid)
		}
		if err := obj.objs.SslFdMap.Put(&key, &val); err != nil {
			t.Fatalf("prefill ssl_fd_map at pid %d: %v", key.Pid, err)
		}
	}
	defer func() {
		for i := uint32(0); i < maxEntries; i++ {
			key := bpf.TinytapUprobeSslFdKey{Pid: keyBase + i}
			_ = obj.objs.SslFdMap.Delete(&key)
		}
	}()

	if _, err := io.WriteString(stdin, "\n"); err != nil {
		t.Fatalf("release helper: %v", err)
	}
	readSSLFdMapTestLine(t, reader) // DONE

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if obj.DropCounts().MapFull > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("MapFull drop count still 0 after a real SSL_set_fd call against a full ssl_fd_map")
}
