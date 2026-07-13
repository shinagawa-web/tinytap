//go:build ignore

// struct pt_regs (needed by BPF_UPROBE's PT_REGS_PARMn macros) comes from
// the vendored vmlinux.h, same as tinytap_kprobe.bpf.c. Userspace uapi
// asm/ptrace.h only exposes the distinct struct user_pt_regs, not this.
// vmlinux.h reflects only this build host's own arch (arm64), which is why
// this program currently only targets arm64 (see gen.go and #156 for the
// x86_64 follow-up).
#include "vmlinux.h"
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

char LICENSE[] SEC("license") = "GPL";
