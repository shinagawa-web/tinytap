# Running Without Full Root

> Part of v0.6.0 production readiness (#155). Documents the minimal Linux capability set tinytap needs, how it was verified empirically (#157), and what's still open.

## The minimal set

```bash
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf=eip ./tinytap
./tinytap   # no sudo
```

| Capability | What it's for | Confirmed by |
|---|---|---|
| `cap_bpf` | Loading BPF programs and maps (`BPF_PROG_LOAD`, `BPF_MAP_CREATE`) | Removing it made `rlimit.RemoveMemlock()` itself fail (see below) |
| `cap_perfmon` | Attaching the tracepoint/kprobe/fentry programs (`perf_event_open`-backed attach paths) | Removing it: `load program: operation not permitted (MEMLOCK may be too low...)` at `BPF_PROG_LOAD` |
| `cap_dac_read_search` | Opening `/sys/kernel/tracing/events/syscalls/*/id` to resolve tracepoint IDs — these files aren't world-readable | Removing it: `permission denied` opening `.../sys_enter_accept4/id` |

Neither `cap_sys_admin` nor `cap_sys_resource` is needed. `cap_net_admin` (mentioned as a maybe in #157) isn't needed either — tinytap only attaches syscall tracepoints, a kprobe, and libssl uprobes, none of which touch netfilter/tc.

## How this was verified

A build of `cmd/tinytap` (arm64, kernel 6.17) had its file capabilities set via `setcap` and was run as a non-root user with `--output stdout`, dropping one capability at a time from the naive starting guess (`cap_dac_read_search,cap_sys_admin,cap_sys_resource,cap_perfmon,cap_bpf`) and checking whether it still attached cleanly:

1. Dropping `cap_sys_admin` — still attached cleanly, including the optional `fentry/tcp_sendmsg_locked` kprobe (`internal/loader/load_kprobe.go`) that captures `sendfile` payload bytes. On this kernel, `BPF_PROG_TYPE_TRACING` attach didn't require it.
2. Dropping `cap_dac_read_search` (in addition) — failed at tracepoint-ID lookup (see table above). Restored.
3. Dropping `cap_sys_resource` (in addition to no `cap_sys_admin`) — still attached cleanly.
4. Dropping `cap_perfmon` or `cap_bpf` individually (from the 3-capability set) — each broke a distinct step (see table above), confirming both are load-bearing.

### Why `cap_sys_resource` turned out not to matter

`internal/loader/load.go` calls `rlimit.RemoveMemlock()` unconditionally before loading anything. Raising `RLIMIT_MEMLOCK`'s hard limit is normally gated on `CAP_SYS_RESOURCE`. But `cilium/ebpf`'s `rlimit.RemoveMemlock()` first probes whether the kernel accounts BPF memory via memcg instead (Linux 5.11+) — if that probe succeeds, it skips touching the rlimit entirely. The probe itself needs `CAP_BPF`. That's why removing `cap_bpf` (not `cap_sys_resource`) is what broke `RemoveMemlock()` in testing above: without `cap_bpf` the probe failed, the code fell back to actually raising the rlimit, and that fell back path is what needs `cap_sys_resource`.

Practically: on a 5.11+ kernel, `cap_bpf` alone covers this path. On an older kernel (5.8–5.10) that lacks memcg-based BPF accounting, tinytap would additionally need `cap_sys_resource` to raise `RLIMIT_MEMLOCK` — untested here since the dev VM runs 6.17.

## Why not an in-process privilege drop

#157's suggested direction also floated dropping capabilities in-process
after `loader.Load()` finishes attaching — on the assumption that once the
initial probes are attached and the ringbuf is open, tinytap never needs to
load a program or attach a probe again for the rest of its run.

That assumption doesn't hold. `cmd/tinytap/tlswatch.go`'s `sslWatcher` wraps
every output sink unconditionally (no opt-out flag) and keeps running for
tinytap's entire lifetime: every time `OnEvent` sees a not-yet-seen pid,
`maybeAttach` spawns a goroutine that discovers whether that process has
loaded libssl and, if so, attaches a fresh `SSL_set_fd` uprobe and a fresh
`SSL_write`/`SSL_read`/`SSL_free` uprobe to it (`AttachSSLSetFd` /
`AttachSSLReadWrite`, both in `internal/loader/load_uprobe.go`) — each a new
`BPF_PROG_LOAD` plus a new `perf_event_open`-backed attach, needing
`cap_bpf` and `cap_perfmon` again, at whatever point during the run that
process happens to first appear.

So dropping `cap_bpf`/`cap_perfmon` right after the initial `Load()` would
silently break TLS capture for every process discovered afterward —
`maybeAttach` only logs the resulting permission error
(`log.Printf("tls: attach SSL_set_fd for pid %d (%s): %v", ...)`), it
doesn't stop tinytap, so the regression wouldn't be obvious from the
outside. Given that, the two currently-shipped capabilities need to stay
live for the whole process, and `setcap` + non-root (above) is the
supported way to run with reduced privilege — no in-process drop is
implemented. This is the "document why it can't" fallback #157 explicitly
allows when in-process dropping isn't practical.

If TLS capture is ever made optional (a `--no-tls` flag, say), a scoped
in-process drop conditioned on that flag would become viable and could be
revisited then.

## Known gaps

- **Kernel version**: this was verified on Linux 6.17. `CAP_PERFMON` as a distinct capability (split from `CAP_SYS_ADMIN`) only exists from 5.8 onward — the same floor tinytap already requires for `BPF_MAP_TYPE_RINGBUF` (see README's Requirements). Kernels between 5.8 and whatever version relaxed `BPF_PROG_TYPE_TRACING` attach checks may still need `cap_sys_admin` for the fentry step specifically; if so, that step degrades gracefully (`tryAttachKprobe` logs and continues without `sendfile` payload bytes — see its doc comment in `load_kprobe.go`), it does not block startup.
- **TLS uprobe path** (`internal/loader/load_uprobe.go`, `SSL_set_fd`/`SSL_read`/`SSL_write`): not exercised by the drop-one-at-a-time test above, since it attaches dynamically to a discovered process's libssl rather than at startup (see previous section). It opens the target process's executable/library (`link.OpenExecutable`) and, per `internal/tls/discover.go`, reads the target process's own `/proc/<pid>/maps` to find where libssl is mapped — reading another user's `/proc/<pid>/maps` needs `ptrace_may_access` to succeed, which may require `cap_sys_ptrace` in addition to the three capabilities above when tinytap runs as a different user than the processes it's watching. Untested here — needs its own empirical pass with a cross-user target process.
- **x86_64**: only tested on arm64. The kprobe payload-capture path uses different mechanisms per arch (arm64 constants vs. x86_64 live KASLR ksyms, see `load_kprobe.go`'s doc comment) — worth re-running this same drop-one-at-a-time test on amd64.
