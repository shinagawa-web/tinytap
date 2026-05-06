package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir . -go-package main Tinytap ../../bpf/tinytap.bpf.c -- -I/usr/include/aarch64-linux-gnu
