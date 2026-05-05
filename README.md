# tinytap — Design Doc

> A learning project: tiny eBPF-based HTTP traffic capture tool.

## 0. Read This First

**This is a personal learning project.** I'm building this to understand eBPF, Linux kernel internals (syscalls, kprobes, ringbuf), and to feel what it's like to write a tcpdump-like tool from scratch.

For production use cases, you should use:

- [kyanos](https://github.com/hengyoush/kyanos) — eBPF traffic analyzer, supports HTTP/Redis/MySQL
- [ptcpdump](https://github.com/mozillazg/ptcpdump) — process-aware tcpdump, eBPF-based
- [eCapture](https://github.com/gojue/ecapture) — for TLS plaintext capture

`tinytap` is intentionally narrower in scope, slower in features, and freer to be incomplete.

The goal is **not** to compete with these. The goal is to learn by building.

---

## 1. What I Want to Learn

This drives every scoping decision. If a feature doesn't help me learn something I want to learn, it gets cut.

| # | Topic | Why |
|---|---|---|
| L1 | eBPF programming model | Write a C program that runs in kernel space |
| L2 | kprobe / syscall hooks | Hook into the kernel without modifying it |
| L3 | ringbuf for kernel→userspace | The standard way to ship events out of eBPF |
| L4 | cilium/ebpf library in Go | Modern Go-based eBPF toolchain |
| L5 | bpf2go workflow | C code → Go bindings, the whole compile pipeline |
| L6 | Linux syscall semantics | accept4, read, write, close — what they actually do |
| L7 | HTTP wire format from raw bytes | Parse HTTP without an HTTP library |
| L8 | Process metadata from /proc | PID → comm, cmdline, etc. |

## 2. What I'm Explicitly Not Trying to Do

- Replace tcpdump
- Compete with kyanos or ptcpdump on features
- Be production-ready
- Support all kernel versions
- Support every protocol
- Be fast at the kernel level
- Get stars on GitHub

## 3. MVP Definition: v0.0.1

**Goal**: when `curl localhost:3000` happens (with a server like `python3 -m http.server` listening on 3000), `tinytap` prints to stdout that it observed kernel-level syscalls related to that connection.

What v0.0.1 does:

1. Loads an eBPF program into the kernel
2. Attaches kprobes to `sys_accept4`, `sys_read`, `sys_write`, `sys_close`
3. Each hook fires an event into a ringbuf containing: PID, syscall name, fd, timestamp, byte count
4. A Go userspace process reads from the ringbuf and prints lines like:
   ```
   [12:34:56.789] pid=12345 (python3) accept4 fd=4
   [12:34:56.790] pid=12345 (python3) read    fd=4 bytes=78
   [12:34:56.790] pid=12345 (python3) write   fd=4 bytes=156
   [12:34:56.791] pid=12345 (python3) close   fd=4
   ```

What v0.0.1 does **not** do:
- Parse HTTP (the bytes are not interpreted, only counted)
- Filter by anything (every syscall from every process is captured)
- Pretty TUI (just stdout)
- Match req/res pairs
- Anything about TLS

This is intentionally less than `strace`. The point is to feel eBPF working end to end.

## 4. v0.1.0: HTTP-aware

Once v0.0.1 works, the next step:

1. Capture the **payload bytes** (not just byte count) for `read` and `write`
2. Buffer per-fd, parse incoming bytes as HTTP/1.1
3. When a complete request line + headers is seen, emit one event
4. When the matching response is seen, pair them and emit a request/response line:
   ```
   [12:34:56.790] pid=12345 GET  /index.html  →  200  156 bytes  (1.2ms)
   ```

This is the "useful demo" version. v0.0.1 is the "I understand the plumbing" version.

## 5. Architecture

```
tinytap/
├── bpf/
│   └── tinytap.bpf.c        # eBPF C program
├── cmd/
│   └── tinytap/
│       └── main.go           # CLI entry, loads eBPF, reads ringbuf
├── internal/
│   ├── loader/               # eBPF program lifecycle (load, attach, detach)
│   ├── events/               # Event struct, ringbuf reader
│   ├── proc/                 # PID → process name lookup via /proc
│   └── parser/               # HTTP parser (added in v0.1.0, empty in v0.0.1)
├── tools/
│   └── gen.go                # //go:generate directives for bpf2go
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── DESIGN.md
```

### Boundaries

- `bpf/` — kernel-side, written in C, compiled by clang
- `internal/loader/` — knows about cilium/ebpf, loads `.o` files, attaches probes
- `internal/events/` — knows about ringbuf semantics, decodes raw event bytes into Go structs
- `internal/proc/` — pure Go, reads /proc, no eBPF
- `internal/parser/` — pure Go, HTTP state machine, no eBPF, no syscalls
- `cmd/tinytap/` — wires everything together

### Why this separation

Because it makes it easy to test the HTTP parser without eBPF, and the proc lookup without HTTP. The eBPF and ringbuf parts are the irreducibly system-dependent parts; everything else can be unit-tested with plain Go.

## 6. Toolchain

| Component | Choice | Why |
|---|---|---|
| eBPF lib | `github.com/cilium/ebpf` | Pure Go, modern, standard for new projects |
| Build | `bpf2go` (part of cilium/ebpf) | Generates Go bindings from C code |
| Compiler | `clang` 14+ | Standard for eBPF, supports BTF |
| Go | 1.22+ | Match my other projects |
| Kernel | Linux 5.4+ | Common on modern Ubuntu, has BTF, ringbuf available 5.8+ — may bump to 5.8+ if ringbuf API gives trouble |
| Architecture | amd64 + arm64 | Need arm64 for Apple Silicon Lima VM |

### Dev environment

Mac (Apple Silicon) + Lima with Ubuntu 24.04. Build and run inside the Lima VM. Edit code on Mac via VS Code's remote SSH or the auto-mounted filesystem.

Setup commands (recorded for future me):

```bash
# Mac side
brew install lima
limactl start --name=tinytap template://ubuntu
limactl shell tinytap

# Inside the VM
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
  build-essential git pkg-config

# Go (apt version is old)
GO_VERSION=1.23.4
ARCH=$(dpkg --print-architecture)  # arm64 on Apple Silicon
wget https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-${ARCH}.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## 7. Event Schema (v0.0.1)

The C struct shared between kernel and userspace:

```c
struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 fd;
    __u32 bytes;       // for read/write; 0 for accept4/close
    __u8  syscall_id;  // 0=accept4, 1=read, 2=write, 3=close
    char  comm[16];    // task command name from bpf_get_current_comm()
};
```

The Go side mirrors this:

```go
type Event struct {
    TimestampNs uint64
    PID         uint32
    TID         uint32
    FD          uint32
    Bytes       uint32
    SyscallID   uint8
    Comm        [16]byte
}
```

For v0.1.0, payload bytes will be added (capped at some MTU-ish size, say 4KB per event, paginated for larger payloads).

## 8. Things I Know I Don't Know Yet

These are the moments I expect to learn the most. They're **listed here precisely because I don't know how to solve them yet**.

| OQ | Question | Where I'll figure it out |
|---|---|---|
| OQ-1 | How to filter by PID inside the eBPF program (vs filtering in userspace) | While writing the C side |
| OQ-2 | How to handle the "read partial buffer" case for HTTP | While writing the parser, v0.1.0 |
| OQ-3 | Whether to use kprobe or tracepoint for syscalls (tracepoint is more stable) | Reading cilium/ebpf docs and other projects |
| OQ-4 | How big should the ringbuf be | Empirically, start at 256KB |
| OQ-5 | How to handle short reads / partial events at userspace | When events start arriving |
| OQ-6 | Whether comm[16] is enough, or I need to follow up with /proc reads | When PIDs collide in interesting ways |

I'm explicitly **not** going to design these in advance. I'll figure them out by writing code and being wrong.

## 9. Anti-Goals (Things I Will Resist)

These are the failure modes I want to actively avoid:

- **Scope creep into being a real tool**: if I find myself adding features because "users would want X", I should stop. There are no users. There is just me, learning.
- **Over-architecting before code exists**: this DESIGN.md is the most architecture I will do upfront. Past this, the structure should evolve from the code.
- **Comparing to kyanos at every step**: kyanos is C, has a team, and does many things. tinytap is a hobbyist Go project. Different categories.
- **Trying to support every kernel version**: I'll target what my Lima VM has. If it works, ship. If someone else's kernel is older, "PR welcome" or "doesn't matter".

## 10. Roadmap (Loose, Subject to Boredom)

| Version | Goal | Status |
|---|---|---|
| v0.0.1 | Hooks fire, events make it to userspace | TBD |
| v0.1.0 | HTTP req/res visible from `curl` to local server | TBD |
| v0.2.0 | Filtering by PID / port | TBD |
| v0.3.0 | Pretty TUI with Bubble Tea | TBD |
| v0.4.0 | TLS plaintext (uprobe on libssl) | TBD, requires real motivation |
| ...    | ...whatever I'm curious about | |

If I lose interest at v0.0.1, that's also fine. v0.0.1 alone is enough to learn what I came to learn.

## 11. License

MIT (assume — confirm before public release).

## 12. References I'm Going to Lean On

- [cilium/ebpf examples](https://github.com/cilium/ebpf/tree/main/examples) — primary reference for the Go side
- [hengyoush/kyanos](https://github.com/hengyoush/kyanos) — when I need to see "how do they actually do this for HTTP"
- [mozillazg/ptcpdump](https://github.com/mozillazg/ptcpdump) — for process-awareness patterns
- [Pixie blog: Debugging with eBPF Part 2](https://blog.px.dev/ebpf-http-tracing/) — the canonical "tracing HTTP via syscalls" walkthrough
- [eunomia eBPF tutorials](https://eunomia.dev/) — readable, hands-on
- Brendan Gregg's blog — for the kernel-side mental model

---

*End of design. Stop reading, start coding.*
