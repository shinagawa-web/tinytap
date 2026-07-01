// Package bpf holds the bpf2go-generated bindings for the kernel-side
// program in bpf/tinytap.bpf.c. The generated files (tinytap_bpfel.go /
// tinytap_bpfeb.go / *.o) are checked in alongside this file; regenerate
// them with `go generate` after editing the C source.
package bpf

// Include both multiarch dirs; clang silently ignores ones that don't
// exist, so this works on amd64 and arm64 hosts without per-arch tweaks.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir . -go-package bpf Tinytap ../../../bpf/tinytap.bpf.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir . -go-package bpf TinytapKprobe ../../../bpf/tinytap_kprobe.bpf.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
