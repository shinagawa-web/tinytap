//go:build ignore

package tools

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir ../cmd/tinytap -go-package main Tinytap ../bpf/tinytap.bpf.c
