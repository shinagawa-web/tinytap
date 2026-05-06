//go:build ignore

#define __TARGET_ARCH_arm64

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

enum syscall_id {
    SYS_ACCEPT4 = 1,
    SYS_READ    = 2,
    SYS_WRITE   = 3,
    SYS_CLOSE   = 4,
};

struct event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u32 bytes;
    __u32 syscall;
    __u8  comm[16];
    __u8  _pad[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// Set by userspace before load. Events from this PID are skipped to avoid
// the feedback loop where logging an event triggers a write kprobe.
volatile const __u32 own_pid = 0;

static __always_inline void submit_event(__u32 syscall, __s32 fd, __u32 bytes)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid == own_pid)
        return;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->ts_ns   = bpf_ktime_get_ns();
    e->pid     = pid;
    e->tid     = (__u32)pid_tgid;
    e->fd      = fd;
    e->bytes   = bytes;
    e->syscall = syscall;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/__arm64_sys_accept4")
int BPF_KPROBE(handle_accept4, struct pt_regs *regs)
{
    int sockfd = (int)PT_REGS_PARM1_CORE(regs);
    submit_event(SYS_ACCEPT4, sockfd, 0);
    return 0;
}

SEC("kprobe/__arm64_sys_read")
int BPF_KPROBE(handle_read, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE(regs);
    __u32 count = (__u32)PT_REGS_PARM3_CORE(regs);
    submit_event(SYS_READ, fd, count);
    return 0;
}

SEC("kprobe/__arm64_sys_write")
int BPF_KPROBE(handle_write, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE(regs);
    __u32 count = (__u32)PT_REGS_PARM3_CORE(regs);
    submit_event(SYS_WRITE, fd, count);
    return 0;
}

SEC("kprobe/__arm64_sys_close")
int BPF_KPROBE(handle_close, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE(regs);
    submit_event(SYS_CLOSE, fd, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
