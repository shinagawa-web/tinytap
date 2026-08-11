//go:build privileged

package loader_test

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
)

func TestSocketProbeSampleSendmsgRecvmsgSecondIovec(t *testing.T) {
	tt, err := loader.Load(0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer tt.Close()

	pid := uint32(os.Getpid())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

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

	const sendmsgMarker = "tinytap-sendmsg-second-iov"
	sendFiller := []byte("filler01")
	sendMarker := []byte(sendmsgMarker)

	clientRC, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatalf("client SyscallConn: %v", err)
	}
	var sendErr error
	if err := clientRC.Write(func(fd uintptr) bool {
		_, sendErr = unix.SendmsgBuffers(int(fd), [][]byte{sendFiller, sendMarker}, nil, nil, 0)
		return sendErr != unix.EAGAIN
	}); err != nil {
		t.Fatalf("Write control: %v", err)
	}
	if sendErr != nil {
		t.Fatalf("SendmsgBuffers: %v", sendErr)
	}

	const recvmsgMarker = "tinytap-recvmsg-second-iov"
	recvPayload := append(append([]byte{}, "filler02"...), recvmsgMarker...)
	if _, err := serverConn.Write(recvPayload); err != nil {
		t.Fatalf("server Write: %v", err)
	}

	recvBuf1 := make([]byte, 8)
	recvBuf2 := make([]byte, len(recvmsgMarker))
	var recvErr error

	clientRecvRC, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatalf("client recv SyscallConn: %v", err)
	}
	if err := clientRecvRC.Read(func(fd uintptr) bool {
		_, _, _, _, recvErr = unix.RecvmsgBuffers(int(fd), [][]byte{recvBuf1, recvBuf2}, nil, unix.MSG_WAITALL)
		return recvErr != unix.EAGAIN
	}); err != nil {
		t.Fatalf("Read control: %v", err)
	}
	if recvErr != nil {
		t.Fatalf("RecvmsgBuffers: %v", recvErr)
	}
	if !bytes.Equal(recvBuf2, []byte(recvmsgMarker)) {
		t.Fatalf("recvBuf2 = %q, want %q (test setup didn't split across two iovecs as expected)", recvBuf2, recvmsgMarker)
	}

	sawSendmsg, sawRecvmsg := false, false
	tt.Reader.SetDeadline(time.Now().Add(5 * time.Second))
	for !sawSendmsg || !sawRecvmsg {
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
		n := int(e.PayloadLen)
		if n > len(e.Payload) {
			n = len(e.Payload)
		}
		sample := e.Payload[:n]
		switch {
		case e.Syscall == events.SyscallSendmsg && bytes.Contains(sample, sendMarker):
			sawSendmsg = true
		case e.Syscall == events.SyscallRecvmsg && bytes.Contains(sample, []byte(recvmsgMarker)):
			sawRecvmsg = true
		}
	}
}
