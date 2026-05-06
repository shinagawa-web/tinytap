package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Event struct {
	Pid  uint32
	Comm [16]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	var objs TinytapObjects
	if err := LoadTinytapObjects(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("__arm64_sys_accept4", objs.HandleAccept4, nil)
	if err != nil {
		log.Fatalf("attach kprobe: %v", err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	log.Println("tinytap running — watching accept4. Press Ctrl-C to stop.")

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
		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		log.Printf("accept4: pid=%-6d comm=%s", e.Pid, comm)
	}
}
