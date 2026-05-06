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

## 0.5. The Dream

While the immediate goal is learning, the long-term vision keeps me oriented while I write the small early versions. I'm allowed to dream.

> **tinytap is the "DevTools Network tab" for everything happening on a local development machine — across processes, across containers, across protocols, across time.**

The browser DevTools Network tab is loved because it makes the otherwise invisible visible: every request, response, header, body, timing, all in one place. But it only sees what the browser does. Once a request leaves the browser, lands at a server, calls another service, hits a DB, comes back — the developer is blind.

`tinytap` aims to be that view, for the **server-side and service-mesh-side** of local development.

### The Four Flagship Capabilities

Of all the directions this could go, these four are what I most want to build:

1. **Cross-container observability** — see traffic flowing in and out of every Docker container on the machine, attributed to the right service. No more "is the request making it into the pod?" guessing.

2. **Cross-service request chains** — when service A calls service B which calls service C, see the whole chain as one trace, not three disconnected captures. Automatic correlation by request ID where possible.

3. **History and replay** — every captured session is recorded to disk in a `.tinytap` file. Open it later. Search it. Filter it. "What was that bug last Thursday?" — not gone forever.

4. **One pane of glass** — HTTP, gRPC, PostgreSQL, MySQL, Redis, WebSocket, all in a single timeline. The current state of local debugging requires a different tool per protocol. tinytap unifies them.

These four together describe the same fundamental thing: **the developer should not be blind to what their machine is doing.** Today they are.

### Why this is allowed to be a fantasy

I may never get past v0.1.0. That's fine. But while I'm writing v0.0.1, I want to know what landscape the code is climbing toward. The design choices of "how do I structure events?" or "how big is the ringbuf?" are different when you're aware that someday this might carry PostgreSQL wire protocol bytes for a 10-service compose stack.

Architecture should be modest. Ambition should be honest.

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
   accept4 pid=12345  tid=12345  fd=3   bytes=0    comm=python3
   write   pid=12345  tid=12346  fd=2   bytes=60   comm=python3
   close   pid=12345  tid=12346  fd=5   bytes=0    comm=python3
   ```

What v0.0.1 does **not** do:
- Parse HTTP (the bytes are not interpreted, only counted)
- Filter by anything (every syscall from every process is captured)
- Pretty TUI (just stdout)
- Match req/res pairs
- Anything about TLS
- Capture HTTP payload syscalls for socket-using code (Python, curl, etc.).
  Their `read`/`write` go through `recvfrom`/`sendto` which are not yet hooked. See #8.

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

## 6. Where tinytap Runs

There are two distinct environments to keep in mind, and they answer two different questions.

### 6.1 Where tinytap is *built and developed*

This is about me. The development environment is **Mac + Lima + Ubuntu VM**, because eBPF only exists on Linux and I work on a Mac. See Section 7 for setup.

This is private to my workflow. It does not constrain users.

### 6.2 Where tinytap is *executed*

This is about the user (which, for now, is also me, but eventually anyone).

**tinytap requires a Linux kernel.** It cannot run natively on macOS or Windows, because eBPF is a Linux kernel technology.

But "requires a Linux kernel" is less restrictive than it sounds, because Linux kernels are everywhere:

| Where the user works | How tinytap runs there |
|---|---|
| Linux desktop / laptop / workstation | Native. Just run the binary. |
| Linux server (cloud VM, on-prem, dev box) | Native. SSH in, run it. |
| Mac (Intel or Apple Silicon) | Inside a Linux VM — Lima, Multipass, OrbStack, UTM, Docker Desktop's VM, etc. |
| Windows | Inside WSL2 (which is a real Linux kernel). |

This pattern — "Mac/Win developers run this through a Linux VM" — is the standard for **all** eBPF tools, including kyanos, ptcpdump, eCapture, bpftrace, and Cilium tooling. tinytap is not unusual here.

### 6.3 Containers are friends, not enemies

A common confusion: "if I'm running my dev stack in Docker on my Mac, can tinytap see inside the containers?"

**Yes.** This is one of eBPF's structural advantages.

A Docker container is just a process (or a tree of processes) running on the host's Linux kernel, isolated by namespaces and cgroups. From the kernel's point of view, container processes are not different from any other processes. eBPF programs attach to kernel events — syscalls, kprobes, tracepoints — which fire for *all* processes, container or not.

So when the layout is:

```
Mac
└── Lima VM (Ubuntu)        ← tinytap runs here
    ├── tinytap (Go binary, sudo)
    └── Docker daemon
        ├── container: api-service
        ├── container: db
        └── container: cache
```

…tinytap, running in the VM as root, observes syscalls from the api-service / db / cache processes too. It sees their network reads and writes the same way it would for a process running directly on the VM.

This is not magic. It's the same reason `htop` on the host shows container processes: they're all just kernel processes.

For the user, this means: **tinytap doesn't need to be installed inside containers**, doesn't need a sidecar, doesn't need the application to be rebuilt with anything. One install on the host, and you see everything below it.

(There's a subtlety: container-aware *attribution* — turning a PID into "this is the api-service container" — is a deliberate feature, slated for v7.x. The kernel sees the PIDs; mapping them back to container names requires reading from Docker / containerd. v0.0.1 just shows raw PIDs.)

### 6.4 What this means for the project

- The README's "Requirements" section will say: "Linux kernel 5.8+. macOS and Windows users run via Lima / WSL / VM."
- I will not pretend to support macOS natively. There is no path to that.
- I will not invest in cross-OS abstractions — there is one OS, Linux, and that's the OS this tool is for.
- The "feels native on Mac" experience is delegated to Lima/OrbStack/etc., which is already a solved problem for the eBPF community.

## 7. Toolchain

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

## 8. Event Schema (v0.0.1)

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

## 9. Things I Know I Don't Know Yet

These are the moments I expect to learn the most. They're **listed here precisely because I don't know how to solve them yet**.

| OQ | Question | Where I'll figure it out |
|---|---|---|
| OQ-1 | How to filter by PID inside the eBPF program (vs filtering in userspace) | While writing the C side |
| OQ-2 | How to handle the "read partial buffer" case for HTTP | While writing the parser, v0.1.0 |
| OQ-3 | Whether to use kprobe or tracepoint for syscalls (tracepoint is more stable) | Reading cilium/ebpf docs and other projects |
| OQ-4 | How big should the ringbuf be | Empirically, start at 256KB |
| OQ-5 | How to handle short reads / partial events at userspace | When events start arriving |
| OQ-6 | Whether comm[16] is enough, or I need to follow up with /proc reads | When PIDs collide in interesting ways |
| OQ-7 | Which syscalls cover all socket I/O? `read`/`write` miss Python (recvfrom/sendto). Add more kprobes (Pixie) or hook at TCP layer (tcp_recvmsg)? | While running v0.0.1 against real python3+curl traffic — see #8 |

I'm explicitly **not** going to design these in advance. I'll figure them out by writing code and being wrong.

## 10. Anti-Goals (Things I Will Resist)

These are the failure modes I want to actively avoid:

- **Scope creep into being a real tool**: if I find myself adding features because "users would want X", I should stop. There are no users. There is just me, learning.
- **Over-architecting before code exists**: this DESIGN.md is the most architecture I will do upfront. Past this, the structure should evolve from the code.
- **Comparing to kyanos at every step**: kyanos is C, has a team, and does many things. tinytap is a hobbyist Go project. Different categories.
- **Trying to support every kernel version**: I'll target what my Lima VM has. If it works, ship. If someone else's kernel is older, "PR welcome" or "doesn't matter".

## 11. Roadmap

The roadmap is split into two layers:

- **Foundation** (v0.x – v1.0): the parts I'm committing to — these are achievable, scoped, and grounded.
- **Vision** (v2.0+): the dream — what tinytap could become if I keep going. These versions have no deadline, no commitment, and no shame in never being built.

The point of writing the Vision down is not to schedule it. It's to make sure that when I'm laying foundations in v0.0.1, I know what they're foundations *for*.

### Foundation — Concrete Steps

| Version | Goal |
|---|---|
| v0.0.1 | Hooks fire, events make it to userspace as raw syscall traces |
| v0.1.0 | HTTP req/res visible from `curl` to local server |
| v0.2.0 | Filtering by PID / port |
| v0.3.0 | Bubble Tea TUI (replaces stdout) |
| v1.0.0 | First public release: stable HTTP/1.1 capture, scrollable history, Wireshark-style detail view, Homebrew formula |

If I lose interest at v0.0.1, that's also fine. v0.0.1 alone is enough to learn what I came to learn.

### Vision — The Four Flagships

The four directions matter most. Numbers are loose; some may swap order based on curiosity. Each flagship is described here with the *experience* it should produce, not just the feature list.

#### v2.x — **Cross-service request chains**

> When service A calls service B which calls service C, see the whole chain as one trace.

- HTTP/2 + gRPC support
- Automatic request correlation by `X-Request-ID` / `traceparent` headers
- Service map: nodes are processes, edges are observed traffic, updated live
- Click a request, see the entire downstream call chain
- "Why is this slow?" answered in one view: which hop dominated, where errors started

The local-development equivalent of distributed tracing — except no instrumentation, no sidecars, no SDKs. Just observation.

#### v3.x — **Database-aware**

> See the SQL queries fired by each request. Catch N+1 in the act.

- PostgreSQL wire protocol parser
- MySQL parser
- Redis RESP parser
- Per-request SQL summary: "this HTTP request issued 47 SELECTs to the same table"
- Automatic N+1 detection (visual highlight, not just a warning)
- Slow query threshold rendering inline with the request that issued it

This makes tinytap stop being a "network tool" and start being a "request lifecycle tool."

#### v4.x — **History and replay**

> Every session is recorded. Open it next week. Search it. Replay it.

- `.tinytap` capture file format (probably extended pcapng or custom)
- `tinytap open old-session.tinytap` — load a past capture
- Full-text search across captured payloads
- Filter by time window, PID, service, status, latency
- Export individual requests as `curl` commands
- Export sessions as Postman / Insomnia / Bruno collections
- Diff two captures: "what changed between yesterday's run and today's"

The shift from "observation tool" to "memory of the development environment."

#### v7.x — **Cross-container observability**

> See what's happening *inside* and *between* containers, attributed to the right service.

- Docker / containerd integration
- Container ID / name appears in every event
- Compose-aware: `tinytap --compose-project myapp` watches all services
- Network namespace traversal: see traffic crossing container boundaries
- "This request entered nginx, was forwarded to app, which queried db" — visible end to end

Container-aware observability without deploying anything inside containers.

### v10.0 — The synthesis

> tinytap becomes "the DevTools Network tab for everything on this machine."

When all four flagships exist together, tinytap is no longer a collection of features — it's a single integrated view:

- One timeline, every protocol
- Every container, every process
- Live now, replayable later
- Search any past session, diff any two
- The local development environment becomes legible

This is the version where a developer no longer has to ask "what's happening?" — they just look.

### What's not on the list (yet)

- TLS plaintext via uprobe on libssl / Go crypto/tls — interesting but huge, slot somewhere between v3 and v7 if motivated
- Production deployment — never. tinytap is for the developer's machine, not their cluster.
- Web UI — possibly as a sibling tool, but the TUI stays primary
- Plugin system — only if the core stabilizes enough to deserve one

## 12. License

MIT (assume — confirm before public release).

## 13. References I'm Going to Lean On

- [cilium/ebpf examples](https://github.com/cilium/ebpf/tree/main/examples) — primary reference for the Go side
- [hengyoush/kyanos](https://github.com/hengyoush/kyanos) — when I need to see "how do they actually do this for HTTP"
- [mozillazg/ptcpdump](https://github.com/mozillazg/ptcpdump) — for process-awareness patterns
- [Pixie blog: Debugging with eBPF Part 2](https://blog.px.dev/ebpf-http-tracing/) — the canonical "tracing HTTP via syscalls" walkthrough
- [eunomia eBPF tutorials](https://eunomia.dev/) — readable, hands-on
- Brendan Gregg's blog — for the kernel-side mental model

---

*End of design. Stop reading, start coding.*
