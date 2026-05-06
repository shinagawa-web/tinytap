package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

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

	log.Println("tinytap running — watching accept4. Press Ctrl-C to stop.")
	log.Println("Check logs: sudo cat /sys/kernel/debug/tracing/trace_pipe")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
}
