//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

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
// the feedback loop where logging an event triggers a write tracepoint.
volatile const __u32 own_pid = 0;

// Layout of /sys/kernel/tracing/events/syscalls/sys_enter_*/format.
// Same shape for every syscall enter tracepoint — only args[] meaning differs.
struct sys_enter_ctx {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            syscall_nr;
    int            _pad;
    unsigned long  args[6];
};

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

SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_accept4(struct sys_enter_ctx *ctx)
{
    submit_event(SYS_ACCEPT4, (__s32)ctx->args[0], 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct sys_enter_ctx *ctx)
{
    submit_event(SYS_READ, (__s32)ctx->args[0], (__u32)ctx->args[2]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct sys_enter_ctx *ctx)
{
    submit_event(SYS_WRITE, (__s32)ctx->args[0], (__u32)ctx->args[2]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_close(struct sys_enter_ctx *ctx)
{
    submit_event(SYS_CLOSE, (__s32)ctx->args[0], 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
