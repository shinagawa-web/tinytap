//go:build ignore

// fentry/tcp_sendmsg_locked — capture page-cache bytes from sendfile.
//
// When Go's http.ServeFile calls sendfile64, the kernel routes the data
// kernel-to-kernel (page cache → socket) without ever passing through
// user space.  tcp_sendmsg_locked fires inside the sendfile64 syscall with
// MSG_SPLICE_PAGES set, giving us the first bio_vec entry and therefore
// the kernel VA of the page we want to sample.
//
// Turning a `struct page *` back into a readable kernel VA needs the two
// per-arch base addresses of the memory map:
//
//   arm64 (VA_BITS=48, no KASAN) — the layout is fixed at build time, so the
//   bases are compile-time constants.  Verified against a live Lima-VM run in
//   PR #68:  va = 0xffff00010da19200 => 0x6666666666666666 (file full of 'f').
//
//   x86_64 — KASLR randomizes page_offset_base and vmemmap_base every boot
//   (and 5-level paging shifts them again), so constants are always wrong.
//   We read the live values through CO-RE kallsyms (`__ksym`) externs instead.
//   Verified against a live lima-x86 (5-level paging + KASLR) bpftrace run in
//   #112:  va = 0xff3f7fd647d18000 => "TINYTAP_TINYTAP_..." (known payload).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Must match tinytap.bpf.c's MAX_PAYLOAD exactly (#36).
#define MAX_PAYLOAD      4096
#define MSG_SPLICE_PAGES 0x8000000

#if defined(__TARGET_ARCH_arm64)

// arm64, VA_BITS=48, no KASAN. Fixed layout, so the bases are constants.
#define VMEMMAP_START     0xfffffdffc0000000ULL
#define PAGE_OFFSET_CONST 0xffff000000000000ULL   // -(1ULL << 48)

#elif defined(__TARGET_ARCH_x86)

// KASLR randomizes these every boot; read the live values at run time.
// Declared as address ksyms (`void`, no const — cilium/ebpf requires the
// .ksyms var's type to be plain Void): cilium/ebpf resolves `&sym` to the
// symbol's kernel address, which we then bpf_probe_read_kernel() to get its
// value.  __weak so a kernel without the symbols (KASLR disabled) still loads —
// sendfile_page_to_va() then falls back to the fixed 4-level layout.
extern void page_offset_base __ksym __weak;
extern void vmemmap_base     __ksym __weak;

// Fixed 4-level defaults, used only when the ksyms are absent.
#define X86_PAGE_OFFSET_DEFAULT 0xffff888000000000ULL
#define X86_VMEMMAP_DEFAULT     0xffffea0000000000ULL

#endif

// Translate a page-cache `struct page *` plus its byte offset into the kernel
// virtual address of the bytes.  Both arches share the same shape:
//   pfn = (page - vmemmap_base) / sizeof(struct page)   // sizeof == 64 => >>6
//   va  = page_offset_base + (pfn << PAGE_SHIFT) + offset
// On arm64 the memstart_addr terms of phys_to_virt cancel, leaving the same
// form with compile-time bases.
static __always_inline u64 sendfile_page_to_va(u64 page, u32 offset)
{
#if defined(__TARGET_ARCH_arm64)
    u64 pfn = (page - VMEMMAP_START) >> 6;   // sizeof(struct page) == 64
    return PAGE_OFFSET_CONST + (pfn << 12) + offset;
#elif defined(__TARGET_ARCH_x86)
    u64 page_offset = 0, vmemmap = 0;
    bpf_probe_read_kernel(&page_offset, sizeof(page_offset), &page_offset_base);
    bpf_probe_read_kernel(&vmemmap, sizeof(vmemmap), &vmemmap_base);
    if (!page_offset)
        page_offset = X86_PAGE_OFFSET_DEFAULT;
    if (!vmemmap)
        vmemmap = X86_VMEMMAP_DEFAULT;
    u64 pfn = (page - vmemmap) >> 6;          // sizeof(struct page) == 64
    return page_offset + (pfn << 12) + offset;
#else
    (void)page;
    (void)offset;
    return 0;   // unsupported arch; the loader only attaches on arm64 / amd64
#endif
}

// Must match the definition in tinytap.bpf.c exactly.
// At load time the loader replaces this map with the one from tinytap.bpf.c
// via MapReplacements so both programs share the same kernel map.
struct sendfile_sample {
    __u32 payload_len;
    __u8  payload[MAX_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);                    // tid
    __type(value, struct sendfile_sample);
} sendfile_sample_map SEC(".maps");

// Per-CPU scratch buffer for staging a sample before it goes into
// sendfile_sample_map. At MAX_PAYLOAD=4096, `struct sendfile_sample` is
// ~4.1 KiB — far past the 512-byte eBPF stack frame limit, so it can no
// longer be a local variable (#36). A per-CPU array map entry lives in the
// map's backing memory instead of the stack, and one entry per CPU is
// enough because this program runs with preemption disabled.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sendfile_sample);
} sendfile_scratch_map SEC(".maps");

SEC("fentry/tcp_sendmsg_locked")
int BPF_PROG(handle_tcp_sendmsg_locked, struct sock *sk, struct msghdr *msg,
             size_t size)
{
    // Only intercept sendfile-style sends (page cache → socket).
    unsigned int msg_flags = BPF_CORE_READ(msg, msg_flags);
    if (!(msg_flags & MSG_SPLICE_PAGES))
        return 0;

    // Verify the iterator carries bio_vec entries.
    u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    if (iter_type != ITER_BVEC)
        return 0;

    // Read the first bio_vec to get the page pointer and byte offset.
    const struct bio_vec *bvec_ptr = BPF_CORE_READ(msg, msg_iter.bvec);
    struct bio_vec bv;
    if (bpf_probe_read_kernel(&bv, sizeof(bv), bvec_ptr) < 0)
        return 0;

    // Derive the kernel virtual address of the page-cache page (see
    // sendfile_page_to_va() for the per-arch base-address handling).
    u64 va = sendfile_page_to_va((u64)bv.bv_page, bv.bv_offset);

    __u32 to_read = bv.bv_len;
    if (to_read > MAX_PAYLOAD)
        to_read = MAX_PAYLOAD;
    if (to_read == 0)
        return 0;

    __u32 zero = 0;
    struct sendfile_sample *s = bpf_map_lookup_elem(&sendfile_scratch_map, &zero);
    if (!s)
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    if (bpf_probe_read_kernel(s->payload, to_read, (void *)(unsigned long)va) < 0)
        return 0;
    s->payload_len = to_read;

    bpf_map_update_elem(&sendfile_sample_map, &tid, s, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
