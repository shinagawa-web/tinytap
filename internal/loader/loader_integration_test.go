//go:build privileged

package loader_test

import (
	"bytes"
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

// TestSocketProbeEmitsWriteEvent verifies that the sys_enter_write tracepoint
// fires and delivers a ringbuf event when this process writes to a TCP socket.
// This confirms the socket probe attachment works end-to-end — unlike
// TestLoaderLoadAttachClose (load+close only) and TestFixtureRingbufDecode
// (fixture program on getpid, not socket probes).
func TestSocketProbeEmitsWriteEvent(t *testing.T) {
	// ownPid=0: the BPF skips events where pid==own_pid; passing 0 means no
	// PID is skipped, so this process's own outgoing socket writes are visible.
	tt, err := loader.Load(0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer tt.Close()

	pid := uint32(os.Getpid())

	// Open a loopback TCP listener so we can write to a real socket fd.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Accept in background so the three-way handshake completes.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	serverConn := <-accepted
	defer serverConn.Close()

	// Write a recognisable payload — fires sys_enter_write.
	const marker = "tinytap-probe-test"
	if _, err := conn.Write([]byte(marker)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Drain the ringbuf until we see an outgoing write event from this process
	// whose payload sample contains our marker, confirming the tracepoint fired.
	tt.Reader.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		rec, err := tt.Reader.Read()
		if err != nil {
			t.Fatalf("ringbuf read: %v", err)
		}
		var e events.Event
		if err := events.Decode(rec.RawSample, &e); err != nil {
			continue
		}
		if e.Pid != pid || e.Syscall != events.SyscallWrite {
			continue
		}
		if !bytes.Contains(e.Payload[:e.PayloadLen], []byte(marker)) {
			continue
		}
		// The write tracepoint fired and the payload reached userspace.
		if e.Fd <= 0 {
			t.Errorf("Fd = %d, want a positive socket fd", e.Fd)
		}
		if e.Bytes != uint32(len(marker)) {
			t.Errorf("Bytes = %d, want %d", e.Bytes, len(marker))
		}
		return
	}
}
