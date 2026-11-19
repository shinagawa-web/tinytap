//go:build privileged

package loader_test

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/shinagawa-web/tinytap/internal/loader"
)

// buildSSLWriteLoopHelper compiles testdata/ssl_write_loop_helper.c with cc.
func buildSSLWriteLoopHelper(t *testing.T, dir string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available, skipping uprobe fixture test")
	}
	outPath := dir + "/ssl_write_loop_helper"
	cmd := exec.Command(cc, "-o", outPath, "testdata/ssl_write_loop_helper.c", "-ldl")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile ssl_write_loop_helper: %v\n%s", err, out)
	}
	return outPath
}

// TestSSLPayloadProbeDropCounts_RingbufReserveFailure drives enough real
// SSL_write(3) calls in a subprocess to overflow the 8 MiB ssl_events ring
// (each struct ssl_event is ~4.1 KiB, so ~2016 events fill it) with nothing
// draining obj.Reader, and confirms the resulting drops are counted rather
// than silently discarded (#290). The ring is sized for every pid on this
// libssl inode to share (#327), not just one, so this test needs
// substantially more writes than a single 1 MiB ring did.
func TestSSLPayloadProbeDropCounts_RingbufReserveFailure(t *testing.T) {
	libsslPath := findLibSSL(t)

	info, err := os.Stat(libsslPath)
	if err != nil {
		t.Fatalf("stat %s: %v", libsslPath, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Skipf("%s has no execute bit set; run `sudo chmod +x %s` before this test", libsslPath, libsslPath)
	}

	helperPath := buildSSLWriteLoopHelper(t, t.TempDir())

	const writes = 4096 // ~2016 fills the 8 MiB ring; comfortably over that
	cmd := exec.Command(helperPath, libsslPath, strconv.Itoa(writes))
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
	if _, err := readLineWithTimeout(reader, 5*time.Second); err != nil {
		t.Fatalf("read READY line: %v", err)
	}

	pid := uint32(cmd.Process.Pid)
	reg := loader.NewSSLRegistry()
	defer func() {
		if err := reg.Close(); err != nil {
			t.Errorf("reg.Close: %v", err)
		}
	}()
	obj, _, err := reg.Shared(libsslPath)
	if err != nil {
		t.Fatalf("Shared: %v", err)
	}
	links, err := loader.AttachSSLReadWrite(obj, pid, libsslPath)
	if err != nil {
		t.Fatalf("AttachSSLReadWrite: %v", err)
	}
	defer func() {
		if err := links.Close(); err != nil {
			t.Errorf("links.Close: %v", err)
		}
	}()

	// Deliberately never read obj.Reader — draining it would prevent the
	// ring from ever filling.
	if _, err := io.WriteString(stdin, "\n"); err != nil {
		t.Fatalf("release helper: %v", err)
	}
	if _, err := readLineWithTimeout(reader, 5*time.Second); err != nil {
		t.Fatalf("read DONE line: %v", err)
	}

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if obj.DropCounts().Ringbuf > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Ringbuf drop count still 0 after %d SSL_write calls with nothing draining ssl_events", writes)
}
