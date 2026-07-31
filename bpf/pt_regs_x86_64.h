/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal x86_64 `struct pt_regs` for tinytap_uprobe.bpf.c.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The uprobe program reads its target functions' arguments through libbpf's
 * PT_REGS_PARMn / PT_REGS_RC macros (bpf/bpf_tracing.h), which need a real,
 * arch-correct `struct pt_regs` at compile time. The vendored bpf/vmlinux.h is
 * an arm64 BTF dump, so its pt_regs carries arm64 registers (regs[0..30]), not
 * x86_64's, and compiling the uprobe for the amd64 target against it fails with
 * "no member named 'di' in 'struct pt_regs'" (see #156). This program uses no
 * CO-RE relocations at all -- it only reads registers, user-space buffers, and
 * its own maps -- so rather than commit a second multi-MB x86_64 BTF dump just
 * to obtain one struct, the amd64 build hand-declares only that struct here and
 * pulls its int types and BPF map enums from the uapi <linux/bpf.h>. The arm64
 * build keeps using vmlinux.h unchanged.
 *
 * WHICH REGISTER NAMES
 * --------------------
 * bpf_tracing.h's x86 branch is guarded by `#if __KERNEL__ || __VMLINUX_H__`:
 * with vmlinux.h it reads the kernel-internal field names (di, si, ax, ...),
 * and *without* it -- our case -- it reads the userspace-ABI names (rdi, rsi,
 * rax, ...). So this struct deliberately mirrors the stable userspace ABI
 * definition in arch/x86/include/uapi/asm/ptrace.h (equivalently the system
 * header /usr/include/x86_64-linux-gnu/asm/ptrace.h), NOT the BTF dump's
 * kernel-internal spelling. Both describe the very same 21-slot register frame
 * the kernel hands a uprobe; only the field names differ (rdi == di, rax == ax,
 * ...) and every offset is identical.
 *
 * HOW TO RE-VERIFY (do this if a future kernel makes you doubt the layout)
 * -----------------------------------------------------------------------
 * Line-by-line against the system uapi header (matches this file's names):
 *   awk '/struct pt_regs {/{f=1} f{print} f&&/};/{exit}' \
 *       /usr/include/x86_64-linux-gnu/asm/ptrace.h   # the __x86_64__ block
 *
 * Or against the running kernel's own BTF (prints the kernel-internal names --
 * di/si/ax map to rdi/rsi/rax here, same order, same offsets):
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c | \
 *       grep -A25 'struct pt_regs {'
 *
 * On FRED-capable kernels the BTF dump wraps cs/ss in a u64-sized union; that
 * does not change any offset, and this program never reads cs/ss anyway (only
 * rdi/rsi/rdx/rcx = PARM1-4 and rax = RC are dereferenced).
 */
#ifndef TINYTAP_PT_REGS_X86_64_H
#define TINYTAP_PT_REGS_X86_64_H

struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
};

#endif /* TINYTAP_PT_REGS_X86_64_H */
