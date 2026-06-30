//go:build privileged

package loader_test

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/shinagawa-web/tinytap/internal/events"
	fixturebpf "github.com/shinagawa-web/tinytap/internal/loader/bpf/fixture"
	"github.com/shinagawa-web/tinytap/internal/loader"
)

// TestLoaderLoadAttachClose verifies that Load() and Close() both return nil.
// It exercises the full attach/detach path through the real tinytap BPF object.
func TestLoaderLoadAttachClose(t *testing.T) {
	tt, err := loader.Load(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := tt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestFixtureRingbufDecode loads the fixture BPF program, triggers it with a
// getpid syscall, and asserts that events.Decode produces a struct whose
// fields match the constants hardcoded in fixture.bpf.c.  This confirms that
// the Go struct layout (field order, sizes, endianness) stays in lockstep with
// the C struct event definition.
func TestFixtureRingbufDecode(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}

	pid := uint32(os.Getpid())

	spec, err := fixturebpf.LoadFixture()
	if err != nil {
		t.Fatalf("load fixture spec: %v", err)
	}
	v, ok := spec.Variables["target_pid"]
	if !ok || v == nil {
		t.Fatal("target_pid variable not found in fixture spec")
	}
	if err := v.Set(pid); err != nil {
		t.Fatalf("set target_pid: %v", err)
	}

	var objs fixturebpf.FixtureObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("load fixture objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_getpid", objs.EmitFixture, nil)
	if err != nil {
		t.Fatalf("attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		t.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	syscall.Getpid() // triggers emit_fixture

	rd.SetDeadline(time.Now().Add(2 * time.Second))
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("read ringbuf: %v", err)
	}

	var e events.Event
	if err := events.Decode(rec.RawSample, &e); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if e.TsNs == 0 {
		t.Error("TsNs: got 0, want > 0")
	}
	if e.Pid != pid {
		t.Errorf("Pid: got %d, want %d", e.Pid, pid)
	}
	if e.Tid == 0 {
		t.Error("Tid: got 0, want > 0")
	}
	if e.Fd != 42 {
		t.Errorf("Fd: got %d, want 42", e.Fd)
	}
	if e.Bytes != 100 {
		t.Errorf("Bytes: got %d, want 100", e.Bytes)
	}
	if e.Syscall != events.SyscallWrite {
		t.Errorf("Syscall: got %d, want %d (SyscallWrite)", e.Syscall, events.SyscallWrite)
	}
	if e.PayloadLen != 5 {
		t.Errorf("PayloadLen: got %d, want 5", e.PayloadLen)
	}
	comm := strings.TrimRight(string(e.Comm[:]), "\x00")
	if comm == "" {
		t.Error("Comm: got empty string, want process name")
	}
	if string(e.Payload[:5]) != "hello" {
		t.Errorf("Payload[:5]: got %q, want \"hello\"", e.Payload[:5])
	}
	if !bytes.Equal(e.Payload[5:], make([]byte, len(e.Payload)-5)) {
		t.Error("Payload[5:]: got non-zero bytes, want all zeros")
	}
}

// TestSocketProbeEmitsWriteEvent verifies that the socket tracepoints fire and
// deliver ringbuf events for both outgoing (sys_enter_write) and incoming
// (sys_exit_read) syscalls on a real TCP socket. This confirms end-to-end
// probe attachment — unlike TestLoaderLoadAttachClose (load+close only) and
// TestFixtureRingbufDecode (fixture getpid program, not socket probes).
func TestSocketProbeEmitsWriteEvent(t *testing.T) {
	// The BPF check is `if (pid == own_pid) return`, so ownPid=0 means only
	// PID 0 (the kernel swapper) is skipped. Our test process is never PID 0,
	// so its socket syscall events pass through to the ringbuf.
	tt, err := loader.Load(0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer tt.Close()

	pid := uint32(os.Getpid())

	// Open a loopback TCP listener so we can exercise real socket fds.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Accept in background; propagate errors so the test fails deterministically
	// instead of blocking forever if Accept stalls.
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- acceptResult{c, err}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	var serverConn net.Conn
	select {
	case res := <-accepted:
		if res.err != nil {
			t.Fatalf("Accept: %v", res.err)
		}
		serverConn = res.conn
	case <-time.After(5 * time.Second):
		t.Fatal("Accept timed out")
	}
	defer serverConn.Close()

	// --- outgoing path ---
	// Write a recognisable marker from the client — fires sys_enter_write.
	const outMarker = "tinytap-write-probe"
	if _, err := conn.Write([]byte(outMarker)); err != nil {
		t.Fatalf("client Write: %v", err)
	}

	// --- incoming path ---
	// Server sends a different marker; the client read call fires
	// sys_enter_read (stash fd+buf) and sys_exit_read (emit with filled buffer).
	const inMarker = "tinytap-read-probe"
	if _, err := serverConn.Write([]byte(inMarker)); err != nil {
		t.Fatalf("server Write: %v", err)
	}
	readBuf := make([]byte, len(inMarker))
	if _, err := io.ReadFull(conn, readBuf); err != nil {
		t.Fatalf("client Read: %v", err)
	}

	// Drain the ringbuf until we see one outgoing write event carrying outMarker
	// and one incoming read event carrying inMarker, both from this process.
	sawWrite, sawRead := false, false
	tt.Reader.SetDeadline(time.Now().Add(5 * time.Second))
	for !sawWrite || !sawRead {
		rec, err := tt.Reader.Read()
		if err != nil {
			t.Fatalf("ringbuf read: %v", err)
		}
		var e events.Event
		if err := events.Decode(rec.RawSample, &e); err != nil {
			continue
		}
		if e.Pid != pid {
			continue
		}
		// Clamp PayloadLen to the array size before slicing.
		n := int(e.PayloadLen)
		if n > len(e.Payload) {
			n = len(e.Payload)
		}
		sample := e.Payload[:n]
		switch {
		case e.Syscall == events.SyscallWrite && bytes.Contains(sample, []byte(outMarker)):
			if e.Fd <= 0 {
				t.Errorf("write event: Fd = %d, want > 0", e.Fd)
			}
			if e.Bytes != uint32(len(outMarker)) {
				t.Errorf("write event: Bytes = %d, want %d", e.Bytes, len(outMarker))
			}
			sawWrite = true
		case e.Syscall == events.SyscallRead && bytes.Contains(sample, []byte(inMarker)):
			if e.Fd <= 0 {
				t.Errorf("read event: Fd = %d, want > 0", e.Fd)
			}
			if e.Bytes != uint32(len(inMarker)) {
				t.Errorf("read event: Bytes = %d, want %d", e.Bytes, len(inMarker))
			}
			sawRead = true
		}
	}
}
