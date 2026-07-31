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
// The SSL uprobes (#147/#146) use no kernel struct access, but their
// PT_REGS_PARMn argument macros are arch-specific (bpf_tracing.h requires
// __TARGET_ARCH_* to be defined) and need a real struct pt_regs at compile
// time. arm64 gets it from the vendored vmlinux.h; x86_64's isn't in that
// arm64 BTF dump, so the C source hand-declares it in bpf/pt_regs_x86_64.h and
// pulls the rest from the uapi <linux/bpf.h> (see #156). Both targets emit an
// arch-tagged object selected by Go build tags.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -output-dir . -go-package bpf TinytapUprobe ../../../bpf/tinytap_uprobe.bpf.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
