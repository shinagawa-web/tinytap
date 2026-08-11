---
title: Event Schema
weight: 13
---

# Event Schema

The kernel-to-userspace event format used by `tinytap`. The C struct lives
in [`bpf/tinytap.bpf.c`](https://github.com/shinagawa-web/tinytap/blob/main/bpf/tinytap.bpf.c)
and the Go struct in [`cmd/tinytap/main.go`](https://github.com/shinagawa-web/tinytap/blob/main/cmd/tinytap/main.go).
They must stay in sync, byte-for-byte. The ringbuf carries one of these per
captured syscall.

## C side (kernel)

```c
enum syscall_id {
    SYS_ACCEPT4  = 1,
    SYS_READ     = 2,
    SYS_WRITE    = 3,
    SYS_CLOSE    = 4,
    SYS_RECVFROM = 5,
    SYS_SENDTO   = 6,
    SYS_RECVMSG  = 7,
    SYS_SENDMSG  = 8,
    SYS_WRITEV   = 9,   // outgoing vectored write; payload sampled across iovecs up to MAX_PAYLOAD
    SYS_READV    = 10,  // incoming vectored read; payload sampled across iovecs at sys_exit, up to MAX_PAYLOAD
    SYS_SENDFILE = 11,  // outgoing zero-copy transfer; bytes = actual transferred count, payload always empty
};

struct event {
    __u64 ts_ns;          // bpf_ktime_get_ns() at the syscall entry
    __u32 pid;            // tgid (the "process id" users see)
    __u32 tid;            // thread id (different from pid for threads in a process)
    __s32 fd;             // file descriptor argument (or -1 if not applicable)
    __u32 bytes;          // requested byte count (read/write/recv/send); 0 for accept4/close
    __u32 syscall;        // enum syscall_id; indicates which hook fired
    __u32 payload_len;    // actual bytes copied into payload[] (0 if no payload captured)
    __u8  comm[16];       // bpf_get_current_comm() — process name, may not be NUL-terminated
    __u8  payload[4096];  // first MAX_PAYLOAD bytes of the user buffer (outgoing only at sys_enter)
};
```

That's 4144 bytes total, with no implicit padding: fields are ordered so
the natural layout aligns to 8 bytes.

## Go side (userspace)

```go
const maxPayload = 4096

type Event struct {
    TsNs       uint64
    Pid        uint32
    Tid        uint32
    Fd         int32
    Bytes      uint32
    Syscall    uint32
    PayloadLen uint32
    Comm       [16]byte
    Payload    [maxPayload]byte
}
```

Decoded from raw ringbuf bytes via `encoding/binary` with little-endian
byte order (arm64 / x86_64 native).

## Field notes

- **`ts_ns`**: kernel-side monotonic clock in nanoseconds. Not wall-clock. Use for relative ordering and latency calculation, not for absolute timestamps.

- **`pid` / `tid`**: `bpf_get_current_pid_tgid()` returns `(tgid << 32) | tid`. `pid` here is the tgid (= user-visible PID); `tid` is the thread id within that group. For single-threaded processes the two are equal.

- **`fd`**: first syscall argument. For `accept4` this is the *listening* socket fd, not the new connection fd (the new fd is the syscall return value, only available at `sys_exit`).

- **`bytes`**: captured at `sys_enter`, so this is the *requested* byte count (e.g. `read(fd, buf, 8192)` records 8192 even if only 80 bytes actually arrive).

- **`syscall`**: enum value from above. The Go side has a parallel `syscallNames` map.

- **`payload_len`**: set to 0 for hooks that don't capture payload (accept4 / close / incoming syscalls at sys_enter). Otherwise `min(MAX_PAYLOAD, bytes)`.

- **`comm`**: kernel's `task_struct.comm`, max 15 chars + NUL. **Not guaranteed NUL-terminated** when exactly 16 chars long; trim trailing NULs before printing.

- **`payload`**: up to `MAX_PAYLOAD` (4096) bytes of the user buffer at `sys_enter`. Only populated for outgoing syscalls (`write` / `sendto` / `sendmsg`).

## Layout (offsets)

| Offset | Size | Field |
|---|---|---|
| 0   | 8   | `ts_ns` |
| 8   | 4   | `pid` |
| 12  | 4   | `tid` |
| 16  | 4   | `fd` |
| 20  | 4   | `bytes` |
| 24  | 4   | `syscall` |
| 28  | 4   | `payload_len` |
| 32  | 16  | `comm[16]` |
| 48  | 4096 | `payload[4096]` |
| Total | 4144 | |

## SSL plaintext event (uprobe)

A second, separate event format emitted by the SSL_write/SSL_read uprobe
program over its own ringbuf (`ssl_events`). This program is a standalone
capability, not wired into the main event ringbuf above, and it carries
no `fd` (SSL-to-fd correlation is a separate probe's job).

```c
enum ssl_op {
    SSL_OP_WRITE = 1, // captured at entry; len is the requested byte count
    SSL_OP_READ  = 2, // captured at return; len is the actual byte count
};

struct ssl_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u64 ssl;             // SSL* value, opaque — never dereferenced
    __u32 op;               // enum ssl_op
    __u32 len;               // see enum ssl_op for entry-vs-return semantics
    __u32 payload_len;       // actual bytes copied into payload[]
    __u32 _pad;              // explicit alignment pad, keeps comm/payload offsets a multiple of 8
    __u8  comm[16];
    __u8  payload[4096];
};
```

That's 4152 bytes total.

- **`op`**: `SSL_OP_WRITE` is captured at `SSL_write`/`SSL_write_ex` entry, where `(ssl, buf, num)` are already valid arguments. `SSL_OP_READ` is captured at `SSL_read`/`SSL_read_ex` *return* instead, since the plaintext buffer is only filled by the time the call returns.

- **`len`**: for writes, the *requested* byte count. For reads, the *actual* byte count, since it's only known at return.

- **`_pad`**: no data; keeps `comm`/`payload` at offsets that are multiples of 8, explicit rather than left to compiler-inserted struct padding.

- **`payload`**: up to 4096 bytes of plaintext, same cap and truncation behavior as the main event's `payload`.

### SSL event layout (offsets)

| Offset | Size | Field |
|---|---|---|
| 0   | 8   | `ts_ns` |
| 8   | 4   | `pid` |
| 12  | 4   | `tid` |
| 16  | 8   | `ssl` |
| 24  | 4   | `op` |
| 28  | 4   | `len` |
| 32  | 4   | `payload_len` |
| 36  | 4   | `_pad` |
| 40  | 16  | `comm[16]` |
| 56  | 4096 | `payload[4096]` |
| Total | 4152 | |
