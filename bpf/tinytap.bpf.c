//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_PAYLOAD 256

enum syscall_id {
    SYS_ACCEPT4  = 1,
    SYS_READ     = 2,
    SYS_WRITE    = 3,
    SYS_CLOSE    = 4,
    SYS_RECVFROM = 5,
    SYS_SENDTO   = 6,
    SYS_RECVMSG  = 7,
    SYS_SENDMSG  = 8,
};

struct event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u32 bytes;
    __u32 syscall;
    __u32 payload_len;
    __u8  comm[16];
    __u8  payload[MAX_PAYLOAD];
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

// Mirror of glibc/Linux 64-bit userspace struct iovec (sys/uio.h).
struct iovec_user {
    void  *iov_base;
    __u64  iov_len;
};

// Mirror of glibc/Linux 64-bit userspace struct msghdr (sys/socket.h).
// Matches the kernel's `struct user_msghdr` byte-for-byte.
struct msghdr_user {
    void              *msg_name;
    __u32              msg_namelen;
    __u32              _pad1;
    struct iovec_user *msg_iov;
    __u64              msg_iovlen;
    void              *msg_control;
    __u64              msg_controllen;
    __s32              msg_flags;
    __u32              _pad2;
};

#define MAX_IOV 8

// Walk a userspace msghdr. Returns total iov_len summed across iovecs
// (capped at MAX_IOV). If out_first_base / out_first_len are non-NULL,
// fills them with the first iovec's base pointer and length — used by
// sendmsg to grab a payload sample from the first chunk.
static __always_inline __u32 read_msghdr(const void *user_msghdr_ptr,
                                         void **out_first_base,
                                         __u32 *out_first_len)
{
    struct msghdr_user msg;
    if (bpf_probe_read_user(&msg, sizeof(msg), user_msghdr_ptr) < 0)
        return 0;

    __u32 total = 0;
    void *first_base = NULL;
    __u32 first_len = 0;

    #pragma unroll
    for (int i = 0; i < MAX_IOV; i++) {
        if ((__u64)i >= msg.msg_iovlen)
            break;
        struct iovec_user iov;
        if (bpf_probe_read_user(&iov, sizeof(iov), &msg.msg_iov[i]) < 0)
            break;
        if (i == 0) {
            first_base = iov.iov_base;
            first_len  = (__u32)iov.iov_len;
        }
        total += (__u32)iov.iov_len;
    }

    if (out_first_base) *out_first_base = first_base;
    if (out_first_len)  *out_first_len  = first_len;
    return total;
}

static __always_inline void submit_event(__u32 syscall, __s32 fd, __u32 bytes,
                                         const void *user_buf, __u32 user_len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid == own_pid)
        return;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->ts_ns       = bpf_ktime_get_ns();
    e->pid         = pid;
    e->tid         = (__u32)pid_tgid;
    e->fd          = fd;
    e->bytes       = bytes;
    e->syscall     = syscall;
    e->payload_len = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (user_buf && user_len > 0) {
        __u32 to_read = user_len;
        if (to_read > MAX_PAYLOAD)
            to_read = MAX_PAYLOAD;
        if (bpf_probe_read_user(&e->payload, to_read, user_buf) == 0)
            e->payload_len = to_read;
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_accept4(struct sys_enter_ctx *ctx)
{
    submit_event(SYS_ACCEPT4, (__s32)ctx->args[0], 0, NULL, 0);
    return 0;
}

// Receive-side at sys_enter: the user buffer is empty (the kernel will
// fill it during the syscall). Issue #13 will capture data at sys_exit.
SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct sys_enter_ctx *ctx)
{
    submit_event(SYS_READ, (__s32)ctx->args[0], (__u32)ctx->args[2], NULL, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct sys_enter_ctx *ctx)
{
    __u32 len = (__u32)ctx->args[2];
    submit_event(SYS_WRITE, (__s32)ctx->args[0], len,
                 (const void *)ctx->args[1], len);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_close(struct sys_enter_ctx *ctx)
{
    submit_event(SYS_CLOSE, (__s32)ctx->args[0], 0, NULL, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int handle_recvfrom(struct sys_enter_ctx *ctx)
{
    submit_event(SYS_RECVFROM, (__s32)ctx->args[0], (__u32)ctx->args[2],
                 NULL, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sendto(struct sys_enter_ctx *ctx)
{
    __u32 len = (__u32)ctx->args[2];
    submit_event(SYS_SENDTO, (__s32)ctx->args[0], len,
                 (const void *)ctx->args[1], len);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int handle_recvmsg(struct sys_enter_ctx *ctx)
{
    __u32 total = read_msghdr((const void *)ctx->args[1], NULL, NULL);
    submit_event(SYS_RECVMSG, (__s32)ctx->args[0], total, NULL, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int handle_sendmsg(struct sys_enter_ctx *ctx)
{
    void *first_buf = NULL;
    __u32 first_len = 0;
    __u32 total = read_msghdr((const void *)ctx->args[1],
                              &first_buf, &first_len);
    submit_event(SYS_SENDMSG, (__s32)ctx->args[0], total,
                 first_buf, first_len);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
