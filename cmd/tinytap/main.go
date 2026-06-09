package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	syscallAccept4  = 1
	syscallRead     = 2
	syscallWrite    = 3
	syscallClose    = 4
	syscallRecvfrom = 5
	syscallSendto   = 6
	syscallRecvmsg  = 7
	syscallSendmsg  = 8
)

const maxPayload = 256

type Event struct {
	TsNs       uint64
	Pid        uint32
	Tid        uint32
	Fd         int32
	Bytes      uint32
	Syscall    uint32
	PayloadLen uint32
	Comm       [16]byte
	Payload    [maxPayload]byte
}

var syscallNames = map[uint32]string{
	syscallAccept4:  "accept4",
	syscallRead:     "read",
	syscallWrite:    "write",
	syscallClose:    "close",
	syscallRecvfrom: "recvfrom",
	syscallSendto:   "sendto",
	syscallRecvmsg:  "recvmsg",
	syscallSendmsg:  "sendmsg",
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	spec, err := LoadTinytap()
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}
	if err := spec.Variables["own_pid"].Set(uint32(os.Getpid())); err != nil {
		log.Fatalf("set own_pid: %v", err)
	}

	var objs TinytapObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()

	attaches := []struct {
		name string
		prog *ebpf.Program
	}{
		{"sys_enter_accept4", objs.HandleAccept4},
		{"sys_enter_read", objs.HandleRead},
		{"sys_enter_write", objs.HandleWrite},
		{"sys_enter_close", objs.HandleClose},
		{"sys_enter_recvfrom", objs.HandleRecvfrom},
		{"sys_enter_sendto", objs.HandleSendto},
		{"sys_enter_recvmsg", objs.HandleRecvmsg},
		{"sys_enter_sendmsg", objs.HandleSendmsg},
		{"sys_exit_read", objs.HandleExitRead},
		{"sys_exit_recvfrom", objs.HandleExitRecvfrom},
		{"sys_exit_recvmsg", objs.HandleExitRecvmsg},
	}
	for _, a := range attaches {
		tp, err := link.Tracepoint("syscalls", a.name, a.prog, nil)
		if err != nil {
			log.Fatalf("attach %s: %v", a.name, err)
		}
		defer tp.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	log.Println("tinytap running — watching accept4/read/write/close/recvfrom/sendto/recvmsg/sendmsg. Press Ctrl-C to stop.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		rd.Close()
	}()

	parser := NewHTTPParser()
	pairer := NewPairer()
	var anchor timeAnchor

	var e Event
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("parse event: %v", err)
			continue
		}
		name := syscallNames[e.Syscall]
		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		line := fmt.Sprintf("%-8s pid=%-6d tid=%-6d fd=%-3d bytes=%-6d comm=%s",
			name, e.Pid, e.Tid, e.Fd, e.Bytes, comm)
		if e.PayloadLen > 0 {
			n := int(e.PayloadLen)
			if n > len(e.Payload) {
				n = len(e.Payload)
			}
			line += " | " + renderPayload(e.Payload[:n])
		}
		log.Println(line)

		for _, h := range parser.Feed(&e) {
			log.Println(renderHTTPEvent(h))
			if pe, ok := pairer.Push(h); ok {
				log.Println(renderPairedEvent(pe, anchor.wallTime(pe.ReqTsNs)))
			}
		}
		if e.Syscall == syscallClose {
			parser.Close(e.Pid, e.Fd)
			pairer.Close(e.Pid, e.Fd)
		}
	}
}

// renderPayload turns a raw byte slice into a single-line printable string.
// Printable ASCII (0x20–0x7E) is kept as-is; CR/LF/TAB are escaped so the
// log stays on one line; everything else becomes `.`.
func renderPayload(p []byte) string {
	out := make([]byte, 0, len(p)+8)
	for _, b := range p {
		switch {
		case b == '\r':
			out = append(out, '\\', 'r')
		case b == '\n':
			out = append(out, '\\', 'n')
		case b == '\t':
			out = append(out, '\\', 't')
		case b >= 0x20 && b <= 0x7e:
			out = append(out, b)
		default:
			out = append(out, '.')
		}
	}
	return string(out)
}
