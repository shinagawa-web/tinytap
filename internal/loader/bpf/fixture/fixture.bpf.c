//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_PAYLOAD 256

// Must stay in lockstep with internal/events/event.go and bpf/tinytap.bpf.c.
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

// Set by the test before loading: only emit events from this PID.
volatile const __u32 target_pid = 0;

// Hardcoded field values the integration test asserts against.
#define FIXTURE_FD      42
#define FIXTURE_BYTES   100
#define FIXTURE_SYSCALL 3 // SYS_WRITE

SEC("tracepoint/syscalls/sys_enter_getpid")
int emit_fixture(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;
    if (target_pid != 0 && pid != target_pid)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns       = bpf_ktime_get_ns();
    e->pid         = pid;
    e->tid         = (__u32)pid_tgid;
    e->fd          = FIXTURE_FD;
    e->bytes       = FIXTURE_BYTES;
    e->syscall     = FIXTURE_SYSCALL;
    e->payload_len = 5;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->payload, "hello", 5);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
