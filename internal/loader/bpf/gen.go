// Package bpf holds the bpf2go-generated bindings for the kernel-side
// program in bpf/tinytap.bpf.c. The generated files (tinytap_bpfel.go /
// tinytap_bpfeb.go / *.o) are checked in alongside this file; regenerate
// them with `go generate` after editing the C source.
package bpf

// Include both multiarch dirs; clang silently ignores ones that don't
// exist, so this works on amd64 and arm64 hosts without per-arch tweaks.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir . -go-package bpf Tinytap ../../../bpf/tinytap.bpf.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
// The kprobe program derives kernel VAs with arch-specific memory-map bases,
// so it must be compiled per target arch (this defines __TARGET_ARCH_x86 /
// __TARGET_ARCH_arm64). bpf2go emits one arch-tagged object per target and Go
// build tags select the right one at build time.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -output-dir . -go-package bpf TinytapKprobe ../../../bpf/tinytap_kprobe.bpf.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
// The SSL_set_fd uprobe (#147) needs no kernel struct access, but its
// PT_REGS_PARMn argument macros are still arch-specific (bpf_tracing.h
// requires __TARGET_ARCH_* to be defined) and, unlike the fentry/CO-RE
// tcp_sendmsg_locked kprobe above, need a real kernel-internal struct
// pt_regs — not available from userspace uapi headers (asm/ptrace.h only
// exposes the distinct struct user_pt_regs), only from a BTF-derived
// vmlinux.h. This repo's vendored vmlinux.h reflects only this arm64 build
// host, so arm64 is the only target for now; x86_64 needs its own BTF dump
// from a real x86_64 host (see #156).
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -output-dir . -go-package bpf TinytapUprobe ../../../bpf/tinytap_uprobe.bpf.c -- -I/usr/include/aarch64-linux-gnu
