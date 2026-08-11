//go:build privileged

package loader

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestSSLFdProbe_Delete_RemovesEntry(t *testing.T) {
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
	ssl, err := strconv.ParseUint(sslHex, 0, 64)
	if err != nil {
		t.Fatalf("parse ssl pointer %q: %v", sslHex, err)
	}

	pid := uint32(cmd.Process.Pid)

	probe, err := AttachSSLSetFd(pid, libsslPath)
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
	readSSLFdMapTestLine(t, reader) // DONE

	deadline := time.Now().Add(1 * time.Second)
	for {
		if _, ok := probe.Lookup(pid, ssl); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ssl_fd_map entry never appeared after a real SSL_set_fd call")
		}
		time.Sleep(10 * time.Millisecond)
	}

	probe.Delete(pid, ssl)

	if _, ok := probe.Lookup(pid, ssl); ok {
		t.Fatal("ssl_fd_map entry still present after Delete")
	}
}
