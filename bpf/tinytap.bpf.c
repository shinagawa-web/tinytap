//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_PAYLOAD 256

// Payload sample from fentry/tcp_sendmsg_locked; keyed by tid.
// Written by the companion kprobe object; consumed at sys_exit_sendfile64.
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

// Layout of /sys/kernel/tracing/events/syscalls/sys_exit_*/format.
// Only the return value matters here.
struct sys_exit_ctx {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            syscall_nr;
    int            _pad;
    long           ret;
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

// Walk a raw userspace iovec array (writev / readv). Returns the total
// byte length across up to MAX_IOV entries; fills out_first_base /
// out_first_len with the first entry so callers can sample its bytes.
static __always_inline __u32 read_iov(const void *iov_user_ptr, __u32 iovcnt,
                                      void **out_first_base,
                                      __u32 *out_first_len)
{
    __u32 total = 0;
    void *first_base = NULL;
    __u32 first_len = 0;

    #pragma unroll
    for (int i = 0; i < MAX_IOV; i++) {
        if ((__u64)i >= iovcnt)
            break;
        struct iovec_user iov;
        if (bpf_probe_read_user(&iov, sizeof(iov),
                                (const struct iovec_user *)iov_user_ptr + i) < 0)
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

// Per-thread state stashed at sys_enter for incoming syscalls (read,
// recvfrom, recvmsg, readv). At sys_enter the user buffer is empty, so
// we remember (fd, buf) keyed by tid and consume it at the matching
// sys_exit, where the buffer is filled and the actual byte count is
// available as the syscall return value.
//
// For read / recvfrom, `buf` is the user buffer pointer.
// For recvmsg, `buf` is the msghdr pointer; the iov is re-walked at
// sys_exit to find the first chunk to sample.
// For readv, `buf` is the iov pointer and `iovcnt` is the vector count.
struct incoming_pending {
    __u32 syscall;
    __s32 fd;
    __u64 buf;       // user pointer; pointer type would block bpf2go codegen
    __u32 iovcnt;    // valid for SYS_READV; zero for all other syscalls
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);                  // tid
    __type(value, struct incoming_pending);
} incoming_pending_map SEC(".maps");

// Optional sendfile body samples, populated by the companion kprobe object
// when fentry/tcp_sendmsg_locked fires before sys_exit_sendfile64.  If the
// kprobe object is not loaded (e.g. fentry unavailable), this map stays
// empty and sendfile events carry no payload.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);                    // tid
    __type(value, struct sendfile_sample);
} sendfile_sample_map SEC(".maps");

// Emit a SYS_SENDFILE event.  If s is non-NULL and carries bytes, the
// page-cache sample from fentry/tcp_sendmsg_locked is included; otherwise
// the event is emitted with byte count only (no payload).
static __always_inline void submit_sendfile_event(__s32 fd, __u32 bytes,
                                                  struct sendfile_sample *s)
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
    e->syscall     = SYS_SENDFILE;
    e->payload_len = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (s && s->payload_len > 0) {
        __builtin_memcpy(e->payload, s->payload, MAX_PAYLOAD);
        e->payload_len = s->payload_len < MAX_PAYLOAD ? s->payload_len : MAX_PAYLOAD;
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

// Record (syscall, fd, buf) for this thread at sys_enter so the matching
// sys_exit can read the now-filled buffer.
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
    bpf_map_update_elem(&incoming_pending_map, &tid, &p, BPF_ANY);
}

// Like stash_incoming but also records the iov count for readv, so
// submit_from_pending walks exactly the right number of entries.
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
    bpf_map_update_elem(&incoming_pending_map, &tid, &p, BPF_ANY);
}

// Look up the stashed (fd, buf) for this thread, emit the event with the
// actual received bytes, then delete the map entry. Called from sys_exit
// of read / recvfrom / recvmsg.
static __always_inline void submit_from_pending(long ret)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct incoming_pending *p =
        bpf_map_lookup_elem(&incoming_pending_map, &tid);
    if (!p)
        return;

    if (ret > 0) {
        __u32 bytes = (__u32)ret;

        if (p->syscall == SYS_RECVMSG) {
            // Re-walk the msghdr to find the first iovec; payload sample
            // comes from that chunk, capped at min(ret, first_len).
            void *first_base = NULL;
            __u32 first_len = 0;
            read_msghdr((const void *)(unsigned long)p->buf,
                        &first_base, &first_len);
            __u32 to_read = bytes;
            if (to_read > first_len)
                to_read = first_len;
            submit_event(p->syscall, p->fd, bytes, first_base, to_read);
        } else if (p->syscall == SYS_READV) {
            // Re-walk the iov array; buf holds the iov pointer and iovcnt
            // holds the actual vector count, both stashed at sys_enter.
            // Using the real iovcnt prevents reading past the end of the
            // array when the caller passes fewer than MAX_IOV vectors.
            void *first_base = NULL;
            __u32 first_len = 0;
            read_iov((const void *)(unsigned long)p->buf, p->iovcnt,
                     &first_base, &first_len);
            __u32 to_read = bytes;
            if (to_read > first_len)
                to_read = first_len;
            submit_event(p->syscall, p->fd, bytes, first_base, to_read);
        } else if (p->syscall == SYS_SENDFILE) {
            // sendfile body bytes are transferred kernel-to-kernel (page
            // cache → socket).  If the companion fentry/tcp_sendmsg_locked
            // kprobe stashed a sample, include it; otherwise emit byte
            // count only.
            struct sendfile_sample *s =
                bpf_map_lookup_elem(&sendfile_sample_map, &tid);
            submit_sendfile_event(p->fd, bytes, s);
            bpf_map_delete_elem(&sendfile_sample_map, &tid);
        } else {
            // read / recvfrom: buf points directly at the receive buffer.
            submit_event(p->syscall, p->fd, bytes,
                         (const void *)(unsigned long)p->buf, bytes);
        }
    }
    // Negative or zero return (error, EAGAIN, EOF): drop without an event.

    bpf_map_delete_elem(&incoming_pending_map, &tid);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_accept4(struct sys_enter_ctx *ctx)
{
    submit_event(SYS_ACCEPT4, (__s32)ctx->args[0], 0, NULL, 0);
    return 0;
}

// Incoming syscalls at sys_enter: stash (fd, buf) for the matching
// sys_exit. The user buffer is empty here; the kernel fills it during
// the syscall.
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
    // Stash the msghdr pointer; sys_exit re-walks it to find the first
    // iovec to sample.
    stash_incoming(SYS_RECVMSG, (__s32)ctx->args[0],
                   (const void *)ctx->args[1]);
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

// Incoming syscalls at sys_exit: consume the stashed (fd, buf) and emit
// a single event with the actual received bytes as payload.

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

// writev: outgoing vectored write.  Walk the iov array for total byte
// count and sample the first chunk, mirroring handle_sendmsg.
SEC("tracepoint/syscalls/sys_enter_writev")
int handle_writev(struct sys_enter_ctx *ctx)
{
    void *first_buf = NULL;
    __u32 first_len = 0;
    __u32 total = read_iov((const void *)ctx->args[1], (__u32)ctx->args[2],
                           &first_buf, &first_len);
    submit_event(SYS_WRITEV, (__s32)ctx->args[0], total, first_buf, first_len);
    return 0;
}

// readv: incoming vectored read.  Stash (fd, iov, iovcnt) at sys_enter
// so the matching sys_exit can re-walk exactly iovcnt entries for a
// payload sample — no more, no less.
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

// sendfile64: outgoing zero-copy transfer (page cache → socket).  The
// body bytes never pass through user space, so no payload is sampled.
// Stash the out_fd at sys_enter; emit the actual transferred byte count
// at sys_exit so the pipeline can advance body wire-byte accounting.
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
    // Unconditionally purge any stale sample.  submit_from_pending deletes
    // it on the normal path, but if own_pid filtering skipped sys_enter
    // (no incoming_pending entry) while fentry still fired, the sample
    // would otherwise leak and eventually fill the map.
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&sendfile_sample_map, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
