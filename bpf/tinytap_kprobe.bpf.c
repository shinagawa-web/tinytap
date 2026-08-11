//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PAYLOAD      4096
#define MSG_SPLICE_PAGES 0x8000000

#if defined(__TARGET_ARCH_arm64)

#define VMEMMAP_START     0xfffffdffc0000000ULL
#define PAGE_OFFSET_CONST 0xffff000000000000ULL

#elif defined(__TARGET_ARCH_x86)

extern void page_offset_base __ksym __weak;
extern void vmemmap_base     __ksym __weak;

#define X86_PAGE_OFFSET_DEFAULT 0xffff888000000000ULL
#define X86_VMEMMAP_DEFAULT     0xffffea0000000000ULL

#endif

static __always_inline u64 sendfile_page_to_va(u64 page, u32 offset)
{
#if defined(__TARGET_ARCH_arm64)
    u64 pfn = (page - VMEMMAP_START) >> 6;
    return PAGE_OFFSET_CONST + (pfn << 12) + offset;
#elif defined(__TARGET_ARCH_x86)
    u64 page_offset = 0, vmemmap = 0;
    bpf_probe_read_kernel(&page_offset, sizeof(page_offset), &page_offset_base);
    bpf_probe_read_kernel(&vmemmap, sizeof(vmemmap), &vmemmap_base);
    if (!page_offset)
        page_offset = X86_PAGE_OFFSET_DEFAULT;
    if (!vmemmap)
        vmemmap = X86_VMEMMAP_DEFAULT;
    u64 pfn = (page - vmemmap) >> 6;
    return page_offset + (pfn << 12) + offset;
#else
    (void)page;
    (void)offset;
    return 0;
#endif
}

struct sendfile_sample {
    __u32 payload_len;
    __u8  payload[MAX_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct sendfile_sample);
} sendfile_sample_map SEC(".maps");

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
    unsigned int msg_flags = BPF_CORE_READ(msg, msg_flags);
    if (!(msg_flags & MSG_SPLICE_PAGES))
        return 0;

    u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    if (iter_type != ITER_BVEC)
        return 0;

    const struct bio_vec *bvec_ptr = BPF_CORE_READ(msg, msg_iter.bvec);
    struct bio_vec bv;
    if (bpf_probe_read_kernel(&bv, sizeof(bv), bvec_ptr) < 0)
        return 0;

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
