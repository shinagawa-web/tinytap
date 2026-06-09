// Package bpf holds the bpf2go-generated bindings for the kernel-side
// program in bpf/tinytap.bpf.c. The generated files (tinytap_bpfel.go /
// tinytap_bpfeb.go / *.o) are checked in alongside this file; regenerate
// them with `go generate` after editing the C source.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir . -go-package bpf Tinytap ../../../bpf/tinytap.bpf.c -- -I/usr/include/aarch64-linux-gnu
