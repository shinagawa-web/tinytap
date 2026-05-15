package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	syscallAccept4 = 1
	syscallRead    = 2
	syscallWrite   = 3
	syscallClose   = 4
)

type Event struct {
	TsNs    uint64
	Pid     uint32
	Tid     uint32
	Fd      int32
	Bytes   uint32
	Syscall uint32
	Comm    [16]byte
	_       [4]byte
}

var syscallNames = map[uint32]string{
	syscallAccept4: "accept4",
	syscallRead:    "read",
	syscallWrite:   "write",
	syscallClose:   "close",
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

	log.Println("tinytap running — watching accept4/read/write/close. Press Ctrl-C to stop.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		rd.Close()
	}()

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
		log.Printf("%-7s pid=%-6d tid=%-6d fd=%-3d bytes=%-6d comm=%s",
			name, e.Pid, e.Tid, e.Fd, e.Bytes, comm)
	}
}
