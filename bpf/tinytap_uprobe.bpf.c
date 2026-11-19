//go:build ignore

#if defined(__TARGET_ARCH_x86)
#include <linux/bpf.h>
#include "pt_regs_x86_64.h"
#else
#include "vmlinux.h"
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include "drops.h"

struct ssl_fd_key {
    __u32 pid;
    __u32 _pad;
    __u64 ssl;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ssl_fd_key);
    __type(value, __s32);
} ssl_fd_map SEC(".maps");

SEC("uprobe/ssl_set_fd")
int BPF_UPROBE(handle_ssl_set_fd, void *ssl, int fd)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_fd_key key = {
        .pid = (__u32)(pid_tgid >> 32),
        .ssl = (__u64)(unsigned long)ssl,
    };
    __s32 fd32 = fd;
    if (bpf_map_update_elem(&ssl_fd_map, &key, &fd32, BPF_ANY) == -E2BIG)
        count_drop(DROP_MAP_FULL);
    return 0;
}

#define MAX_SSL_PAYLOAD 4096

enum ssl_op {
    SSL_OP_WRITE = 1,
    SSL_OP_READ  = 2,
    SSL_OP_FREE  = 3,
};

struct ssl_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u64 ssl;
    __u32 op;
    __u32 len;
    __u32 payload_len;
    __u32 _pad;
    __u8  comm[16];
    __u8  payload[MAX_SSL_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} ssl_events SEC(".maps");

struct ssl_read_pending {
    __u64 ssl;
    __u64 buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ssl_read_pending);
} ssl_read_pending_map SEC(".maps");

struct ssl_read_ex_pending {
    __u64 ssl;
    __u64 buf;
    __u64 readbytes_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ssl_read_ex_pending);
} ssl_read_ex_pending_map SEC(".maps");

static __always_inline void submit_ssl_event(__u32 op, __u64 ssl, __u32 len,
                                              const void *user_buf, __u32 user_len)
{
    struct ssl_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
    if (!e) {
        count_drop(DROP_RINGBUF);
        return;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->ts_ns       = bpf_ktime_get_ns();
    e->pid         = (__u32)(pid_tgid >> 32);
    e->tid         = (__u32)pid_tgid;
    e->ssl         = ssl;
    e->op          = op;
    e->len         = len;
    e->payload_len = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (user_buf && user_len > 0) {
        __u32 to_read = user_len;
        if (to_read > MAX_SSL_PAYLOAD)
            to_read = MAX_SSL_PAYLOAD;
        if (bpf_probe_read_user(&e->payload, to_read, user_buf) == 0)
            e->payload_len = to_read;
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("uprobe/ssl_write")
int BPF_UPROBE(handle_ssl_write, void *ssl, void *buf, int num)
{
    if (num <= 0)
        return 0;
    submit_ssl_event(SSL_OP_WRITE, (__u64)(unsigned long)ssl, (__u32)num,
                      buf, (__u32)num);
    return 0;
}

SEC("uprobe/ssl_write_ex")
int BPF_UPROBE(handle_ssl_write_ex, void *ssl, void *buf, __u64 num)
{
    if (num == 0)
        return 0;
    __u32 n = num > 0xffffffff ? 0xffffffff : (__u32)num;
    submit_ssl_event(SSL_OP_WRITE, (__u64)(unsigned long)ssl, n, buf, n);
    return 0;
}

SEC("uprobe/ssl_read")
int BPF_UPROBE(handle_ssl_read, void *ssl, void *buf, int num)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_pending p = {
        .ssl = (__u64)(unsigned long)ssl,
        .buf = (__u64)(unsigned long)buf,
    };
    if (bpf_map_update_elem(&ssl_read_pending_map, &tid, &p, BPF_ANY) == -E2BIG)
        count_drop(DROP_MAP_FULL);
    return 0;
}

SEC("uretprobe/ssl_read")
int BPF_URETPROBE(handle_ssl_read_ret, int ret)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_pending *p = bpf_map_lookup_elem(&ssl_read_pending_map, &tid);
    if (!p)
        return 0;
    struct ssl_read_pending pending = *p;
    bpf_map_delete_elem(&ssl_read_pending_map, &tid);

    if (ret <= 0)
        return 0;

    submit_ssl_event(SSL_OP_READ, pending.ssl, (__u32)ret,
                      (const void *)(unsigned long)pending.buf, (__u32)ret);
    return 0;
}

SEC("uprobe/ssl_read_ex")
int BPF_UPROBE(handle_ssl_read_ex, void *ssl, void *buf, __u64 num, __u64 *readbytes)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_ex_pending p = {
        .ssl           = (__u64)(unsigned long)ssl,
        .buf           = (__u64)(unsigned long)buf,
        .readbytes_ptr = (__u64)(unsigned long)readbytes,
    };
    if (bpf_map_update_elem(&ssl_read_ex_pending_map, &tid, &p, BPF_ANY) == -E2BIG)
        count_drop(DROP_MAP_FULL);
    return 0;
}

SEC("uretprobe/ssl_read_ex")
int BPF_URETPROBE(handle_ssl_read_ex_ret, int ret)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_ex_pending *p = bpf_map_lookup_elem(&ssl_read_ex_pending_map, &tid);
    if (!p)
        return 0;
    struct ssl_read_ex_pending pending = *p;
    bpf_map_delete_elem(&ssl_read_ex_pending_map, &tid);

    if (ret != 1)
        return 0;

    __u64 n = 0;
    if (bpf_probe_read_user(&n, sizeof(n), (const void *)(unsigned long)pending.readbytes_ptr) < 0)
        return 0;
    if (n == 0)
        return 0;

    __u32 n32 = n > 0xffffffff ? 0xffffffff : (__u32)n;
    submit_ssl_event(SSL_OP_READ, pending.ssl, n32,
                      (const void *)(unsigned long)pending.buf, n32);
    return 0;
}

SEC("uprobe/ssl_free")
int BPF_UPROBE(handle_ssl_free, void *ssl)
{
    submit_ssl_event(SSL_OP_FREE, (__u64)(unsigned long)ssl, 0, NULL, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
