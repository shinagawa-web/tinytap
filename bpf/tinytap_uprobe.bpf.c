//go:build ignore

// BPF_UPROBE's PT_REGS_PARMn macros need a real, arch-correct struct pt_regs
// at compile time. arm64 gets it from the vendored vmlinux.h (a BTF dump of
// this build host's arm64 kernel). x86_64's pt_regs is not in that arm64 dump,
// and userspace uapi asm/ptrace.h on arm64 only exposes struct user_pt_regs --
// so rather than vendor a second multi-MB x86_64 BTF dump for a program that
// uses no CO-RE relocations, the amd64 build hand-declares just that one struct
// in pt_regs_x86_64.h and takes its int types / map enums from <linux/bpf.h>.
// See gen.go and #156.
#if defined(__TARGET_ARCH_x86)
#include <linux/bpf.h>
#include "pt_regs_x86_64.h"
#else
#include "vmlinux.h"
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// (pid, SSL*) -> fd, populated by a uprobe on SSL_set_fd(ssl, fd). Consumed
// later by the SSL_write/SSL_read uprobe (#146) to attribute captured
// plaintext to the connection already tracked via the existing
// accept4/close fd lifecycle hooks in tinytap.bpf.c.
//
// Both SSL_set_fd arguments are read directly from registers — no OpenSSL
// struct layout required, so this stays stable across OpenSSL/BoringSSL
// versions (see #144, #145).
//
// Known gap: only calls through the public SSL_set_fd(ssl, fd) API are
// observed. Code that instead wires up the fd via BIO_new_socket() +
// SSL_set_bio(ssl, bio, bio) never calls SSL_set_fd and won't appear here.
// Accepted limitation (#144, #147) — not solved by this program.
struct ssl_fd_key {
    __u32 pid;
    __u32 _pad;   // keep ssl 8-byte aligned; mirrors incoming_pending's _pad
    __u64 ssl;    // SSL* value, opaque — never dereferenced
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ssl_fd_key);
    __type(value, __s32);            // fd
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
    bpf_map_update_elem(&ssl_fd_map, &key, &fd32, BPF_ANY);
    return 0;
}

// SSL_write/SSL_read plaintext capture (#146). SSL_write's (ssl, buf, num)
// are valid arguments at entry, so it's captured with a single uprobe. For
// SSL_read the plaintext buffer is only filled once the call returns, so
// entry stashes (ssl, buf) keyed by tid and a uretprobe reads the actual
// byte count off the return value and copies the now-filled buffer. The
// `_ex` variants (SSL_write_ex/SSL_read_ex) exist on OpenSSL >= 1.1.1 and
// report success via a 0/1 return instead of a byte count — SSL_read_ex's
// actual length instead comes from its `size_t *readbytes` out-param, read
// back via bpf_probe_read_user once the uretprobe confirms success.
#define MAX_SSL_PAYLOAD 4096

enum ssl_op {
    SSL_OP_WRITE = 1, // captured at entry; len is the requested byte count
    SSL_OP_READ  = 2, // captured at return; len is the actual byte count
    SSL_OP_FREE  = 3, // captured at SSL_free entry; len/payload are unused
};

struct ssl_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u64 ssl;             // SSL* value, opaque — never dereferenced
    __u32 op;               // enum ssl_op
    __u32 len;               // see enum ssl_op for entry-vs-return semantics
    __u32 payload_len;       // actual bytes copied into payload[]
    __u32 _pad;
    __u8  comm[16];
    __u8  payload[MAX_SSL_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // Smaller than tinytap.bpf.c's 8 MiB `events` ring (#36): that ring is
    // sized for every syscall across every traced process, while this one
    // only ever sees traffic from the single pid(s) this uprobe program is
    // explicitly attached to.
    __uint(max_entries, 1 << 20);
} ssl_events SEC(".maps");

// (ssl, buf) stashed at SSL_read/SSL_read_ex entry, keyed by tid, so the
// matching uretprobe can read the now-filled buffer. Separate maps per
// symbol because the two uretprobes read the actual length differently
// (return value vs *readbytes out-param) and dispatching on a single
// shared map would need an extra tag to tell them apart for no benefit.
struct ssl_read_pending {
    __u64 ssl;
    __u64 buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // tid
    __type(value, struct ssl_read_pending);
} ssl_read_pending_map SEC(".maps");

struct ssl_read_ex_pending {
    __u64 ssl;
    __u64 buf;
    __u64 readbytes_ptr; // user pointer to the size_t *readbytes out-param
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // tid
    __type(value, struct ssl_read_ex_pending);
} ssl_read_ex_pending_map SEC(".maps");

static __always_inline void submit_ssl_event(__u32 op, __u64 ssl, __u32 len,
                                              const void *user_buf, __u32 user_len)
{
    struct ssl_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
    if (!e)
        return;

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

// int SSL_write(SSL *ssl, const void *buf, int num)
SEC("uprobe/ssl_write")
int BPF_UPROBE(handle_ssl_write, void *ssl, void *buf, int num)
{
    if (num <= 0)
        return 0;
    submit_ssl_event(SSL_OP_WRITE, (__u64)(unsigned long)ssl, (__u32)num,
                      buf, (__u32)num);
    return 0;
}

// int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
SEC("uprobe/ssl_write_ex")
int BPF_UPROBE(handle_ssl_write_ex, void *ssl, void *buf, __u64 num)
{
    if (num == 0)
        return 0;
    __u32 n = num > 0xffffffff ? 0xffffffff : (__u32)num;
    submit_ssl_event(SSL_OP_WRITE, (__u64)(unsigned long)ssl, n, buf, n);
    return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num) — entry: stash (ssl, buf).
SEC("uprobe/ssl_read")
int BPF_UPROBE(handle_ssl_read, void *ssl, void *buf, int num)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_pending p = {
        .ssl = (__u64)(unsigned long)ssl,
        .buf = (__u64)(unsigned long)buf,
    };
    bpf_map_update_elem(&ssl_read_pending_map, &tid, &p, BPF_ANY);
    return 0;
}

// ret is the actual byte count on success, <= 0 on failure/EOF.
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

// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) —
// entry: stash (ssl, buf, &readbytes).
SEC("uprobe/ssl_read_ex")
int BPF_UPROBE(handle_ssl_read_ex, void *ssl, void *buf, __u64 num, __u64 *readbytes)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_ex_pending p = {
        .ssl           = (__u64)(unsigned long)ssl,
        .buf           = (__u64)(unsigned long)buf,
        .readbytes_ptr = (__u64)(unsigned long)readbytes,
    };
    bpf_map_update_elem(&ssl_read_ex_pending_map, &tid, &p, BPF_ANY);
    return 0;
}

// ret is 1 on success, 0 on failure — the actual byte count instead comes
// from *readbytes, only valid to read back once ret confirms success.
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

// void SSL_free(SSL *ssl) — signals this connection's teardown (#173). Unlike
// SSL_set_fd, SSL_free is called exactly once per SSL object regardless of
// how its BIO/fd was wired (confirmed for curl's custom-BIO path too, which
// never calls SSL_set_fd but does call SSL_free on every connection close —
// see #167's investigation), so it's a reliable (pid, SSL*)-scoped analog of
// the close(2) syscall that already drives Pairer.Close for fd-keyed
// connections. Carries no payload — len is 0 and payload_len stays 0.
SEC("uprobe/ssl_free")
int BPF_UPROBE(handle_ssl_free, void *ssl)
{
    submit_ssl_event(SSL_OP_FREE, (__u64)(unsigned long)ssl, 0, NULL, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
