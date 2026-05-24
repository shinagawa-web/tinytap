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

## 1. What tinytap becomes

> **tinytap is the "DevTools Network tab" for everything happening on a local development machine — across processes, across containers, across protocols, across time.**

The browser DevTools Network tab is loved because it makes the otherwise invisible visible: every request, response, header, body, timing, all in one place. But it only sees what the browser does. Once a request leaves the browser, lands at a server, calls another service, hits a DB, comes back — the developer is blind.

`tinytap` brings that view to the **server-side and service-mesh-side** of local development.

### The Four Flagship Capabilities

These four are what tinytap is building toward:

1. **Cross-container observability** — see traffic flowing in and out of every Docker container on the machine, attributed to the right service. No more "is the request making it into the pod?" guessing.

2. **Cross-service request chains** — when service A calls service B which calls service C, see the whole chain as one trace, not three disconnected captures. Automatic correlation by request ID where possible.

3. **History and replay** — every captured session is recorded to disk in a `.tinytap` file. Open it later. Search it. Filter it. "What was that bug last Thursday?" — not gone forever.

4. **One pane of glass** — HTTP, gRPC, PostgreSQL, MySQL, Redis, WebSocket, all in a single timeline. The current state of local debugging requires a different tool per protocol. tinytap unifies them.

These four together describe the same fundamental thing: **the developer should not be blind to what their machine is doing.** Today they are.

Architecture is modest. Ambition is honest.

---

## 2. Terminology

These terms appear throughout the doc, the code, and the issue tracker. They are deliberately **process-relative** — "from whose point of view?" matters.

| Term | Meaning |
|---|---|
| **Outgoing syscall** | A syscall that writes data *out of* a process address space: `write`, `sendto`, `sendmsg`, `writev`. The user buffer is already populated at `sys_enter`, so the payload can be sampled on entry. |
| **Incoming syscall** | A syscall that reads data *into* a process address space: `read`, `recvfrom`, `recvmsg`, `readv`. The user buffer is empty at `sys_enter` — the kernel fills it during the syscall, so the payload is only observable at `sys_exit` (with the return value telling us how much was actually filled). |
| **send-side** / **receive-side** | Synonyms for outgoing / incoming, common in libbpf and Pixie writing. Acceptable once a paragraph has already grounded the direction; avoid as the *first* mention because they sound like they refer to the protocol direction (request vs response) when they actually refer to the syscall family. |

### Protocol mapping (HTTP)

`tinytap` is process-oriented, not protocol-aware. The same syscall carries the **request** on one side and the **response** on the other depending on who is calling it:

| Process | Outgoing payload = | Incoming payload = |
|---|---|---|
| HTTP server (e.g. `python3 -m http.server`) | response | request |
| HTTP client (e.g. `curl`) | request | response |

So "the HTTP response" is *not* a synonym for "outgoing payload" — it depends which process is being observed. When protocol direction matters, write it out: "the HTTP response (server's outgoing payload)" rather than just "the send-side payload".

## 3. What I'm Explicitly Not Trying to Do

- Replace tcpdump
- Compete with kyanos or ptcpdump on features
- Be production-ready
- Support all kernel versions
- Support every protocol
- Be fast at the kernel level
- Get stars on GitHub

## 4. v0.1.0: HTTP-aware

Now that the plumbing works (see Roadmap §10 / closed issues #1-#3, #8), the next step:

1. Capture the **payload bytes** (not just byte count) for `read` and `write`
2. Buffer per-fd, parse incoming bytes as HTTP/1.1
3. When a complete request line + headers is seen, emit one event
4. When the matching response is seen, pair them and emit a request/response line:
   ```
   [12:34:56.790] pid=12345 GET  /index.html  →  200  156 bytes  (1.2ms)
   ```

This is the "useful demo" version.

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
│   └── parser/               # HTTP parser
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

(There's a subtlety: container-aware *attribution* — turning a PID into "this is the api-service container" — is a deliberate feature, slated for v7.x. The kernel sees the PIDs; mapping them back to container names requires reading from Docker / containerd. For now tinytap just shows raw PIDs.)

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

## 8. Roadmap

Moved to [#19](https://github.com/shinagawa-web/tinytap/issues/19) and pinned.

## 9. License

MIT (assume — confirm before public release).

## 10. References I'm Going to Lean On

- [cilium/ebpf examples](https://github.com/cilium/ebpf/tree/main/examples) — primary reference for the Go side
- [hengyoush/kyanos](https://github.com/hengyoush/kyanos) — when I need to see "how do they actually do this for HTTP"
- [mozillazg/ptcpdump](https://github.com/mozillazg/ptcpdump) — for process-awareness patterns
- [Pixie blog: Debugging with eBPF Part 2](https://blog.px.dev/ebpf-http-tracing/) — the canonical "tracing HTTP via syscalls" walkthrough
- [eunomia eBPF tutorials](https://eunomia.dev/) — readable, hands-on
- Brendan Gregg's blog — for the kernel-side mental model

---

*End of design. Stop reading, start coding.*
