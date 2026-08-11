---
title: Internals
weight: 16
---

# Internals

How eBPF and tinytap actually get the payload bytes: the three kernel-side
observation points, the ring buffer design constraints that shaped them, and
the libssl uprobe mechanism that decrypts TLS traffic. This page stops at
capture; see [How It Works]({{< relref "how-it-works" >}}) for the eBPF
background and build pipeline, and [Usage]({{< relref "usage" >}}) for the
JSONL shape the captured bytes end up in.

## One picture

```text
┌──────────────────────────── kernel ─────────────────────────────┐
│                                                                  │
│ [A] tracepoint/syscalls/sys_{enter,exit}_*                      │
│     bpf/tinytap.bpf.c              ────────────► ringbuf events (8 MiB)
│     accept4 read write close recvfrom sendto                    │
│     recvmsg sendmsg writev readv sendfile64                     │
│         ▲                                                       │
│         │ hash sendfile_sample_map (tid → 4096 B)                │
│         │                                                       │
│ [B] fentry/tcp_sendmsg_locked                                   │
│     bpf/tinytap_kprobe.bpf.c    (sendfile's body, read straight │
│                                   off the page cache, before it  │
│                                   ever reaches a socket buffer)  │
│                                                                   │
│ [C] uprobe/uretprobe on libssl.so                                │
│     bpf/tinytap_uprobe.bpf.c       ────────────► ringbuf ssl_events (1 MiB)
│     SSL_write / SSL_read / SSL_set_fd / SSL_free                 │
│                                     ────────────► hash ssl_fd_map │
└────────────────────────────────────────────────────────────────┘
            │ events.Decode                 │ events.DecodeSSL
            ▼                               ▼
      capture() (main pipeline)     captureTLS() (one pair per pid)
```

Three independent observation points converge on the same downstream
pipeline. It decodes the ring buffer record, feeds it to the HTTP parser,
and pairs request with response. TLS support added a new *entry point*, not
a second capture engine.

## Why three separate eBPF objects

| | Attach point | Sees | Output | If it fails to load |
|---|---|---|---|---|
| A `tinytap.bpf.c` | syscall tracepoints | Plaintext HTTP bytes, fd lifecycle | ringbuf `events` | Fatal, this is the main object |
| B `tinytap_kprobe.bpf.c` | `fentry/tcp_sendmsg_locked` | `sendfile`'s body, which bypasses the socket buffer entirely | writes into A's `sendfile_sample_map` | Logged and skipped, `tryAttachKprobe` never fails `Load` |
| C `tinytap_uprobe.bpf.c` | libssl uprobes | TLS plaintext | ringbuf `ssl_events` + hash `ssl_fd_map` | Attached per pid, after the fact, only for processes that need it |

The three are built and loaded as three separate ELF objects instead of one,
because their load prerequisites differ:

- A attaches to syscall tracepoints only, which is close to kernel-version-independent. It's the object every install depends on.
- B requires BTF and `fentry` support (kernel 5.5 or newer). Some kernels don't have it.
- C requires the target process to already have `libssl` mapped, and is attached long after startup, per pid, as processes are discovered.

Bundling B or C's program into A's object would mean a kernel that can't
satisfy B's or C's prerequisites fails to load A too, taking down the
entire main capture path over a program that was always meant to be
optional. Splitting the optional observation points into their own objects
means `tryAttachKprobe` can log `sendfile payload capture disabled` and move
on, and libssl discovery can fail per pid without touching syscall capture
for every other process on the box. The trade for that isolation, on the
kernel side, is a shared map: A and B's objects load independently, but B's
`MapReplacements` binds its `sendfile_sample_map` to the very map A already
declared, so the sample it captures in kernel space lands exactly where A's
`sys_exit_sendfile64` handler expects it.

## The ring buffer: a fixed reserve, and what actually gated throughput

`bpf_ringbuf_reserve(&events, sizeof(*e), 0)` always reserves a full
`sizeof(struct event)`, currently 4096 bytes of payload plus a small fixed
header, even for a 12-byte response. Reserving only the sample's actual
length instead looks like the obvious alternative, but it doesn't compile:
the verifier requires the size argument to `bpf_ringbuf_reserve` to be a
compile-time constant, not a value computed at runtime. Every event pays
for the full 4096-plus bytes regardless of its actual size.

Because each event costs a fixed amount of ring space, ring size and
`MAX_PAYLOAD` are directly coupled: a larger `MAX_PAYLOAD` shrinks how many
events fit in a given ring before it fills up. Draining speed matters just
as much as capacity. `events.Decode` reads each event with hand-rolled
`binary.LittleEndian` calls and `copy()`, avoiding `encoding/binary`'s
reflection-based path for the `[4096]byte` payload field, since reflection
over a field that size is expensive enough to bottleneck how fast the ring
can be drained. With that decode path, the ring's current size, 8 MiB
(`1 << 23` bytes), is enough headroom to avoid drops under normal load.

## The 512-byte stack limit, and the scratch map that works around it

A local variable inside an eBPF program lives on the program's stack, and
that stack is capped at 512 bytes by the verifier (see [How It
Works]({{< relref "how-it-works" >}})'s constraints table), a hard limit
that isn't a tunable. `struct sendfile_sample` holds up to 4096 bytes of
captured body. Declared as an ordinary local (`struct sendfile_sample s;`),
it blows the 512-byte stack on its own before the program does anything
else, and gets rejected at load time.

Object A's `struct event` carries the same 4096-byte payload and never hits
this limit, but only because it never becomes a stack local in the first
place. `submit_event` writes directly into the buffer `bpf_ringbuf_reserve`
hands back, which lives in the ring buffer, not on the stack. Object B
(`tinytap_kprobe.bpf.c`, the `sendfile` path) can't reuse that trick, since
it has no ring buffer of its own to reserve into for this intermediate
value, so it needs an actual place to hold the bytes it reads off the page
cache before it can hand them to A. That place is a map used purely as
scratch space, not for key-based lookups:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sendfile_sample);   // 4096+ bytes
} sendfile_scratch_map SEC(".maps");
```

A map's value storage sits outside the 512-byte stack entirely, so putting
the struct there sidesteps the limit the same way object A's ring buffer
pointer does. `BPF_MAP_TYPE_PERCPU_ARRAY` gives every CPU its own private
copy of that single element; `bpf_map_lookup_elem(&sendfile_scratch_map,
&zero)` returns whichever copy belongs to the CPU the program happens to be
running on. eBPF programs run with preemption disabled, so two invocations
can never be mid-flight on the same CPU at the same time, and one slot per
CPU is therefore enough, with no locking required.

The bytes travel from the page cache into `sendfile_scratch_map` (B's
private scratch slot, one per CPU), get copied from there into
`sendfile_sample_map` (shared with object A via `MapReplacements`), and are
picked up by `tinytap.bpf.c`'s `sys_exit_sendfile64` handler, keyed by
`tid`.

## TLS: reading plaintext through a uprobe

### Why a uprobe

At the syscall layer, `write`/`read` see TLS records: ciphertext. The only
place decrypted plaintext exists is at the boundary between the application
and libssl, `SSL_write()`'s input buffer and `SSL_read()`'s output buffer
once it's filled. That boundary is the only place left to hook.

A uprobe is a breakpoint patched into a resolved file offset inside the
target binary. `cilium/ebpf`'s `link.OpenExecutable(path).Uprobe(symbol,
prog, &link.UprobeOptions{PID: pid})` resolves the symbol's offset from the
ELF's dynamic symbol table, and the kernel traps execution at that offset in
every process that has the file mapped, filtered down to the given `PID`.
Two consequences follow directly from that mechanism:

Statically-linked OpenSSL is invisible to this path, unless it's the
process's own executable. tinytap resolves the uprobe target two ways,
first by scanning `/proc/<pid>/maps` for a mapped `libssl.so(.N)*`, and if
that's absent, by falling back to checking the process's own executable
(`/proc/<pid>/exe`) for the four required symbols. This is what makes
Node.js builds that statically link OpenSSL into the `node` binary work.
Go's `crypto/tls` doesn't use libssl at all, under any linking mode, so it's
unreachable by either path (see [Current Limitations]({{< relref
"limitations" >}})).

The target file also has to be executable. `link.OpenExecutable` requires
it, and Debian/Ubuntu ship `libssl.so.3` as `0644`. tinytap deliberately
doesn't `chmod` it itself; the fix is `sudo chmod +x <path>` on the
operator's side (see [Troubleshooting]({{< relref "troubleshooting" >}})).

### The four symbols

| Symbol | Probe | Why |
|---|---|---|
| `SSL_write` / `SSL_write_ex` | uprobe (entry) | The plaintext is already in `buf` when the call starts |
| `SSL_read` / `SSL_read_ex` | uprobe (entry) + uretprobe (return) | `buf` is empty at entry, only the return has the decrypted bytes |
| `SSL_set_fd` | uprobe (entry) | Records the `(pid, SSL*) → fd` mapping, nothing else |
| `SSL_free` | uprobe (entry) | Connection-close signal, tears down parser/pairer state and clears the `ssl_fd_map` entry |

`SSL_read`'s two-probe shape is the same enter/return split the
plain-syscall side uses for `read`/`recvfrom`/`recvmsg` (stash at entry,
submit once the buffer is actually filled): the same problem gets the same
fix in a different layer. The `_ex` variants only exist in OpenSSL 1.1.1+,
so they're attached on a best-effort basis. `link.ErrNoSymbol` on those two
is skipped rather than treated as a failure, while the four base symbols
are required. `SSL_read_ex` reports its byte count through an output
parameter rather than a return value, so its uretprobe reads that `size_t
*` back out of the caller's memory with `bpf_probe_read_user` instead of
trusting the return register.

Throughout, `SSL*` is treated as an opaque pointer value, a map key, never
dereferenced. tinytap never reads OpenSSL's internal struct layout, which
is what makes it independent of OpenSSL and BoringSSL's version-to-version
struct changes; tools that peek inside `SSL*` have to track that by hand.

### Two identity spaces

HTTP pairing needs a stable "same connection" key. On the plaintext path
that's `(pid, fd)`. TLS breaks that assumption for some clients:

- nginx and Python's `ssl` call `SSL_set_fd(ssl, fd)`. The fd is recoverable from `ssl_fd_map`.
- curl builds its own `BIO` via `BIO_new_socket()` + `SSL_set_bio()` and never calls `SSL_set_fd`. The fd is never in the map, for that connection, ever.

tinytap keys on whichever identity is actually available:

```go
{pid, fd,  sslFallback: false}   // fd known
{pid, ssl, sslFallback: true }   // fd never resolved
```

`captureTLS` decides per event by attempting `fdProbe.Lookup(pid, ssl)`. On
a hit, the SSL event is converted via `tls.FromSSL` into an ordinary
`events.Event` (`SSL_write` becomes a synthetic `write`, `SSL_read` becomes
a synthetic `read`) and fed into the same plaintext-path `Parser.Feed`. On
a miss, it goes through a separate `Parser.FeedSSL` that's keyed on
`(pid, SSL*)` instead. `sslFallback` is set explicitly from which branch
fired, not inferred from `fd == 0`, so a real fd is never confused with an
absent one by coincidence.

`SSL_free` tears down whichever side the connection was actually keyed on:
a resolved fd closes the plaintext-style `(pid, fd)` state, an unresolved
one closes the `(pid, SSL*)` state. Either way, `SSL_free` also clears the
now-stale `ssl_fd_map` entry for that `(pid, SSL*)` key from user space, so
a long-lived process reusing `SSL*` pointer values across connections
doesn't accumulate entries forever.

## Dynamic attach

tinytap doesn't know in advance which pids terminate TLS, so it doesn't
attach uprobes at startup. Instead, every event that reaches the main
capture loop is checked against a `seen` set; the first time a given pid
shows up, discovery for that pid runs in its own goroutine, so a slow
`/proc` scan or ELF parse never blocks the main drain loop.

Immediately after `exec`, a process may not have `libssl` mapped yet
because the dynamic linker hasn't caught up. Discovery retries up to 8
times, 25 ms apart, before giving up, which is enough for `curl` in
practice. Once libssl is found and its four required symbols are confirmed
present, tinytap attaches `SSL_set_fd` first, then the read/write/free
uprobes, and starts a dedicated `captureTLS` goroutine, with its own ring
buffer reader, its own `Parser`, and its own `Pairer`, for that pid. A
dedicated instance matters because the plaintext-path `Parser` for the same
`(pid, fd)` is still receiving that connection's ciphertext `write`/`read`
bytes; feeding both plaintext and ciphertext for the same connection into
one `Parser` would corrupt the stream. The ciphertext still reaches the
plaintext `Parser`, but since it never resembles HTTP, it eventually ages
out as `abandoned`, a side effect, not a bug.

Because eBPF observes the host kernel, a process inside a container is just
another host process under a different PID namespace: `/proc/<pid>/root/`
resolves straight through to the container's filesystem, so libssl
discovery needs no container-specific code at all.
