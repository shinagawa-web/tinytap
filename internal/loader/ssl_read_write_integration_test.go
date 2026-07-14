//go:build privileged && arm64

// This test accesses SSLPayloadProbe.Reader directly, which only exists on
// the real arm64 implementation (load_uprobe.go) — the non-arm64 stub
// (load_uprobe_other.go) has no such field, since AttachSSLReadWrite always
// fails there before returning a probe. TestAttachSSLReadWrite_UnsupportedArch
// in load_uprobe_other_test.go covers that stub behavior on every other arch.

package loader_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
)

// buildSSLWriteHelper compiles testdata/ssl_write_helper.c with cc.
func buildSSLWriteHelper(t *testing.T, dir string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available, skipping uprobe fixture test")
	}
	outPath := dir + "/ssl_write_helper"
	cmd := exec.Command(cc, "-o", outPath, "testdata/ssl_write_helper.c", "-ldl")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile ssl_write_helper: %v\n%s", err, out)
	}
	return outPath
}

// TestAttachSSLReadWrite_RealWriteCall drives a real SSL_write(3) call in a
// subprocess against the system's real libssl.so.3 and confirms
// AttachSSLReadWrite's ringbuf carries the captured plaintext (#146).
//
// SSL_read isn't exercised here: capturing it for real needs a completed
// TLS handshake over a connected socket (a much larger fixture), and the
// entry+uretprobe correlation it needs is otherwise identical to the
// SSL_write path this test already exercises end-to-end. The full
// curl-to-nginx path (both directions, live) is covered by #146's manual
// verification step.
func TestAttachSSLReadWrite_RealWriteCall(t *testing.T) {
	libsslPath := findLibSSL(t)

	info, err := os.Stat(libsslPath)
	if err != nil {
		t.Fatalf("stat %s: %v", libsslPath, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Skipf("%s has no execute bit set; run `sudo chmod +x %s` before this test", libsslPath, libsslPath)
	}

	helperPath := buildSSLWriteHelper(t, t.TempDir())

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
	readyLine, err := readLineWithTimeout(reader, 5*time.Second)
	if err != nil {
		t.Fatalf("read READY line: %v", err)
	}

	var sslHex string
	if _, err := fmt.Sscanf(readyLine, "READY %s", &sslHex); err != nil {
		t.Fatalf("parse READY line %q: %v", readyLine, err)
	}
	wantSSL, err := strconv.ParseUint(sslHex, 0, 64)
	if err != nil {
		t.Fatalf("parse ssl pointer %q: %v", sslHex, err)
	}

	pid := uint32(cmd.Process.Pid)
	probe, err := loader.AttachSSLReadWrite(pid, libsslPath)
	if err != nil {
		t.Fatalf("AttachSSLReadWrite: %v", err)
	}
	defer func() {
		if err := probe.Close(); err != nil {
			t.Errorf("probe.Close: %v", err)
		}
	}()

	type result struct {
		record []byte
		err    error
	}
	recordCh := make(chan result, 1)
	go func() {
		rec, err := probe.Reader.Read()
		recordCh <- result{rec.RawSample, err}
	}()

	if _, err := io.WriteString(stdin, "\n"); err != nil {
		t.Fatalf("release helper: %v", err)
	}
	if _, err := readLineWithTimeout(reader, 5*time.Second); err != nil {
		t.Fatalf("read DONE line: %v", err)
	}

	var raw []byte
	select {
	case res := <-recordCh:
		if res.err != nil {
			t.Fatalf("read ssl ringbuf: %v", res.err)
		}
		raw = res.record
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ssl ringbuf event")
	}

	var got events.SSLEvent
	if err := events.DecodeSSL(raw, &got); err != nil {
		t.Fatalf("DecodeSSL: %v", err)
	}

	if got.Pid != pid {
		t.Errorf("Pid = %d, want %d", got.Pid, pid)
	}
	if got.SSL != wantSSL {
		t.Errorf("SSL = %#x, want %#x", got.SSL, wantSSL)
	}
	if got.Op != events.SSLOpWrite {
		t.Errorf("Op = %d, want SSLOpWrite (%d)", got.Op, events.SSLOpWrite)
	}
	wantPlaintext := []byte("hello-tinytap-146")
	if got.Len != uint32(len(wantPlaintext)) {
		t.Errorf("Len = %d, want %d", got.Len, len(wantPlaintext))
	}
	if !bytes.Equal(got.Payload[:got.PayloadLen], wantPlaintext) {
		t.Errorf("Payload = %q, want %q", got.Payload[:got.PayloadLen], wantPlaintext)
	}
}
