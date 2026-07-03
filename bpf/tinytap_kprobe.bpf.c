//go:build ignore

// fentry/tcp_sendmsg_locked — capture page-cache bytes from sendfile.
//
// When Go's http.ServeFile calls sendfile64, the kernel routes the data
// kernel-to-kernel (page cache → socket) without ever passing through
// user space.  tcp_sendmsg_locked fires inside the sendfile64 syscall with
// MSG_SPLICE_PAGES set, giving us the first bio_vec entry and therefore
// the kernel VA of the page we want to sample.
//
// The VA formula below is arm64-specific (VA_BITS=48, no KASAN).  The
// computed address is verified against a live Lima-VM run in PR #68:
//   va = 0xffff00010da19200  =>  0x6666666666666666  (file full of 'f')

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Must match tinytap.bpf.c's MAX_PAYLOAD exactly (#36).
#define MAX_PAYLOAD      4096
#define MSG_SPLICE_PAGES 0x8000000

// arm64, VA_BITS=48, no KASAN.
#define VMEMMAP_START     0xfffffdffc0000000ULL
#define PAGE_OFFSET_CONST 0xffff000000000000ULL   // -(1ULL << 48)

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

    // Derive the kernel virtual address of the page-cache page.
    // phys_to_virt(pa) = PAGE_OFFSET + pa - memstart_addr (arm64), and
    // pa = pfn * PAGE_SIZE where pfn = (bv_page - VMEMMAP_START) / 64.
    // The memstart_addr terms cancel: va = PAGE_OFFSET + pfn * 4096 + offset.
    u64 pfn = ((u64)bv.bv_page - VMEMMAP_START) >> 6;  // sizeof(struct page)==64
    u64 va  = PAGE_OFFSET_CONST + (pfn << 12) + bv.bv_offset;

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
