//go:build ignore

#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include "drops.h"

#define MAX_PAYLOAD 4096

struct sendfile_sample {
    __u32 payload_len;
    __u8  payload[MAX_PAYLOAD];
};

enum syscall_id {
    SYS_ACCEPT4  = 1,
    SYS_READ     = 2,
    SYS_WRITE    = 3,
    SYS_CLOSE    = 4,
    SYS_RECVFROM = 5,
    SYS_SENDTO   = 6,
    SYS_RECVMSG  = 7,
    SYS_SENDMSG  = 8,
    SYS_WRITEV   = 9,
    SYS_READV    = 10,
    SYS_SENDFILE = 11,
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
    __uint(max_entries, 1 << 23);
} events SEC(".maps");

volatile const __u32 own_pid = 0;

struct sys_enter_ctx {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            syscall_nr;
    int            _pad;
    unsigned long  args[6];
};

struct sys_exit_ctx {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            syscall_nr;
    int            _pad;
    long           ret;
};

struct iovec_user {
    void  *iov_base;
    __u64  iov_len;
};

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

static __always_inline int read_msghdr_iov(const void *user_msghdr_ptr,
                                           struct iovec_user **out_iov,
                                           __u32 *out_iovlen)
{
    struct msghdr_user msg;
    if (bpf_probe_read_user(&msg, sizeof(msg), user_msghdr_ptr) < 0)
        return -1;

    *out_iov    = msg.msg_iov;
    *out_iovlen = (__u32)msg.msg_iovlen;
    return 0;
}

#define IOV_ACTUAL_LEN_UNBOUNDED 0xFFFFFFFFU

static __always_inline __u32 iov_sample_budget(int i)
{
    switch (i) {
    case 0:  return 2048;
    case 1:  return 1024;
    case 2:  return 1024;
    default: return 0;
    }
}

static __always_inline __u32 fill_iov_payload(const void *iov_user_ptr, __u32 iovcnt,
                                              __u32 actual_len, struct event *e)
{
    __u32 total = 0;
    __u32 filled = 0;
    __u32 remaining = actual_len;
    int truncated = 0;

    #pragma unroll
    for (int i = 0; i < MAX_IOV; i++) {
        if ((__u64)i >= iovcnt)
            break;
        struct iovec_user iov;
        if (bpf_probe_read_user(&iov, sizeof(iov),
                                (const struct iovec_user *)iov_user_ptr + i) < 0)
            break;

        __u32 len = (__u32)iov.iov_len;
        total += len;

        __u32 avail = len;
        if (avail > remaining)
            avail = remaining;

        __u32 budget = iov_sample_budget(i);
        if (!truncated && budget > 0 && filled <= MAX_PAYLOAD - budget) {
            __u32 to_read = avail;
            if (to_read > budget)
                to_read = budget;
            if (to_read > 0) {
                if (bpf_probe_read_user(e->payload + filled, to_read, iov.iov_base) == 0)
                    filled += to_read;
                else
                    truncated = 1;
            }
            if (to_read < avail)
                truncated = 1;
        } else if (avail > 0) {
            truncated = 1;
        }
        remaining -= avail;
    }

    e->payload_len = filled;
    return total;
}

struct incoming_pending {
    __u32 syscall;
    __s32 fd;
    __u64 buf;
    __u32 iovcnt;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct incoming_pending);
} incoming_pending_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct sendfile_sample);
} sendfile_sample_map SEC(".maps");

static __always_inline void submit_sendfile_event(__s32 fd, __u32 bytes,
                                                  struct sendfile_sample *s)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid == own_pid)
        return;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop(DROP_RINGBUF);
        return;
    }

    e->ts_ns       = bpf_ktime_get_ns();
    e->pid         = pid;
    e->tid         = (__u32)pid_tgid;
    e->fd          = fd;
    e->bytes       = bytes;
    e->syscall     = SYS_SENDFILE;
    e->payload_len = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (s && s->payload_len > 0) {
        __u32 n = s->payload_len < MAX_PAYLOAD ? s->payload_len : MAX_PAYLOAD;
        if (bpf_probe_read_kernel(e->payload, n, s->payload) == 0)
            e->payload_len = n;
    }

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void submit_event(__u32 syscall, __s32 fd, __u32 bytes,
                                         const void *user_buf, __u32 user_len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid == own_pid)
        return;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop(DROP_RINGBUF);
        return;
    }

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

static __always_inline void submit_event_iov(__u32 syscall, __s32 fd,
                                             const void *iov_ptr, __u32 iovcnt,
                                             __u32 actual_len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid == own_pid)
        return;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop(DROP_RINGBUF);
        return;
    }

    e->ts_ns   = bpf_ktime_get_ns();
    e->pid     = pid;
    e->tid     = (__u32)pid_tgid;
    e->fd      = fd;
    e->syscall = syscall;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 total = fill_iov_payload(iov_ptr, iovcnt, actual_len, e);
    e->bytes = (actual_len == IOV_ACTUAL_LEN_UNBOUNDED) ? total : actual_len;

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void stash_incoming(__u32 syscall, __s32 fd,
                                           const void *buf)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((__u32)(pid_tgid >> 32) == own_pid)
        return;

    __u32 tid = (__u32)pid_tgid;
    struct incoming_pending p = {
        .syscall = syscall,
        .fd      = fd,
        .buf     = (__u64)(unsigned long)buf,
    };
    if (bpf_map_update_elem(&incoming_pending_map, &tid, &p, BPF_ANY) == -E2BIG)
        count_drop(DROP_MAP_FULL);
}

static __always_inline void stash_incoming_iov(__u32 syscall, __s32 fd,
                                               const void *iov_ptr,
                                               __u32 iovcnt)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((__u32)(pid_tgid >> 32) == own_pid)
        return;

    __u32 tid = (__u32)pid_tgid;
    struct incoming_pending p = {
        .syscall = syscall,
        .fd      = fd,
        .buf     = (__u64)(unsigned long)iov_ptr,
        .iovcnt  = iovcnt,
    };
    if (bpf_map_update_elem(&incoming_pending_map, &tid, &p, BPF_ANY) == -E2BIG)
        count_drop(DROP_MAP_FULL);
}

static __always_inline void submit_from_pending(long ret)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct incoming_pending *p =
        bpf_map_lookup_elem(&incoming_pending_map, &tid);
    if (!p)
        return;

    if (ret > 0) {
        __u32 bytes = (__u32)ret;

        if (p->syscall == SYS_RECVMSG || p->syscall == SYS_READV) {
            submit_event_iov(p->syscall, p->fd,
                             (const void *)(unsigned long)p->buf, p->iovcnt,
                             bytes);
        } else if (p->syscall == SYS_SENDFILE) {
            struct sendfile_sample *s =
                bpf_map_lookup_elem(&sendfile_sample_map, &tid);
            submit_sendfile_event(p->fd, bytes, s);
            bpf_map_delete_elem(&sendfile_sample_map, &tid);
        } else {
            submit_event(p->syscall, p->fd, bytes,
                         (const void *)(unsigned long)p->buf, bytes);
        }
    }

    bpf_map_delete_elem(&incoming_pending_map, &tid);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_accept4(struct sys_enter_ctx *ctx)
{
    submit_event(SYS_ACCEPT4, (__s32)ctx->args[0], 0, NULL, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct sys_enter_ctx *ctx)
{
    stash_incoming(SYS_READ, (__s32)ctx->args[0],
                   (const void *)ctx->args[1]);
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
    stash_incoming(SYS_RECVFROM, (__s32)ctx->args[0],
                   (const void *)ctx->args[1]);
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
    struct iovec_user *iov;
    __u32 iovlen;
    if (read_msghdr_iov((const void *)ctx->args[1], &iov, &iovlen) < 0)
        return 0;
    stash_incoming_iov(SYS_RECVMSG, (__s32)ctx->args[0], iov, iovlen);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int handle_sendmsg(struct sys_enter_ctx *ctx)
{
    struct iovec_user *iov;
    __u32 iovlen;
    if (read_msghdr_iov((const void *)ctx->args[1], &iov, &iovlen) < 0)
        return 0;
    submit_event_iov(SYS_SENDMSG, (__s32)ctx->args[0], iov, iovlen,
                     IOV_ACTUAL_LEN_UNBOUNDED);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_exit_read(struct sys_exit_ctx *ctx)
{
    submit_from_pending(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int handle_exit_recvfrom(struct sys_exit_ctx *ctx)
{
    submit_from_pending(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int handle_exit_recvmsg(struct sys_exit_ctx *ctx)
{
    submit_from_pending(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int handle_writev(struct sys_enter_ctx *ctx)
{
    submit_event_iov(SYS_WRITEV, (__s32)ctx->args[0],
                     (const void *)ctx->args[1], (__u32)ctx->args[2],
                     IOV_ACTUAL_LEN_UNBOUNDED);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int handle_readv(struct sys_enter_ctx *ctx)
{
    stash_incoming_iov(SYS_READV, (__s32)ctx->args[0],
                       (const void *)ctx->args[1], (__u32)ctx->args[2]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int handle_exit_readv(struct sys_exit_ctx *ctx)
{
    submit_from_pending(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendfile64")
int handle_sendfile(struct sys_enter_ctx *ctx)
{
    stash_incoming(SYS_SENDFILE, (__s32)ctx->args[0], NULL);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendfile64")
int handle_exit_sendfile(struct sys_exit_ctx *ctx)
{
    submit_from_pending(ctx->ret);
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&sendfile_sample_map, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
