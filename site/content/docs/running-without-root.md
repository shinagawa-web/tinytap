---
title: Running Without Full Root
weight: 3
---

# Running Without Full Root

`sudo ./tinytap` is the simplest path, but tinytap doesn't need full root.

## The minimal set

Plaintext HTTP capture (syscall tracepoints, ringbuf) needs three
capabilities on every architecture:

```bash
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf=eip ./tinytap
./tinytap   # no sudo
```

That's enough for the core capture path everywhere, and for the optional
`sendfile` payload-capture kprobe on arm64 — but **not** for that same
kprobe on x86_64, which additionally needs `cap_syslog` (see the table
below). Its failure degrades gracefully either way (sendfile events just
carry no payload bytes), so this only matters if you want full-fidelity
`sendfile` capture on x86_64:

```bash
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_syslog=eip ./tinytap
./tinytap   # no sudo
```

`cap_syslog` only helps on hosts with `kernel.kptr_restrict` at 0 or 1. At 2
the kernel hides symbol addresses from every process including root, and
x86_64 `sendfile` payload capture is simply unavailable — see
[When `cap_syslog` is and isn't enough](#when-cap_syslog-is-and-isnt-enough)
below.

TLS capture (the `SSL_set_fd`/`SSL_write`/`SSL_read`/`SSL_free` libssl
uprobes) needs `cap_sys_admin` on top of the base three — see
[Why TLS capture needs `cap_sys_admin`](#why-tls-capture-needs-cap_sys_admin)
below for why. Combined with the x86_64 kprobe requirement above, the full
set is:

```bash
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog=eip ./tinytap
./tinytap   # no sudo
```

**The binary must live on a filesystem mounted without `nosuid`.** The
kernel silently drops file capabilities (not just the setuid/setgid bits) at
exec time for binaries on a `nosuid` mount — `setcap` itself succeeds,
`getcap` still shows the capabilities, but the process starts with none of
them and fails as if `setcap` had never been run (`/tmp` is commonly
`nosuid` — check with `findmnt -T <path>` before relying on `setcap`
anywhere new).

| Capability | What it's for |
|---|---|
| `cap_bpf` | Loading BPF programs and maps (`BPF_PROG_LOAD`, `BPF_MAP_CREATE`) |
| `cap_perfmon` | Attaching the tracepoint/kprobe/fentry programs (`perf_event_open`-backed attach paths) |
| `cap_dac_read_search` | Opening `/sys/kernel/tracing/events/syscalls/*/id` to resolve tracepoint IDs — these files aren't world-readable |
| `cap_sys_admin` | TLS only: dynamically registering a new uprobe (`SSL_set_fd` et al.) at an arbitrary file+offset |
| `cap_syslog` | x86_64 only: reading real (non-zeroed) kernel symbol addresses from `/proc/kallsyms` for the `sendfile` payload-capture kprobe |

`cap_sys_resource` is never needed (see below for why). `cap_net_admin`
isn't needed either — tinytap only attaches syscall tracepoints, a kprobe,
and libssl uprobes, none of which touch netfilter/tc.

## When `cap_syslog` is and isn't enough

`cap_syslog` covers the x86_64 kprobe's `/proc/kallsyms` read only at some
`kptr_restrict` levels:

| `kptr_restrict` | `perf_event_paranoid` | Without `cap_syslog` | With `cap_syslog` | As root |
|---|---|---|---|---|
| 0 | ≤ 1 | works | works | works |
| 0 | ≥ 2 | disabled | works | works |
| 1 | any | disabled | works | works |
| 2 | any | disabled | **disabled** | **disabled** |

Practical consequence: **on a `kptr_restrict=2` host, x86_64 `sendfile`
payload capture is unavailable at any privilege level** — no capability
set, not even running as root, restores it. The failure is still graceful
(`sendfile` events pair correctly, they just carry no payload bytes), so
tinytap remains usable; only full-fidelity `sendfile` bodies are lost.
arm64 is unaffected throughout — it uses compile-time constants and never
reads `/proc/kallsyms`.

## Why `cap_sys_resource` turned out not to matter

tinytap calls `rlimit.RemoveMemlock()` unconditionally before loading
anything. Raising `RLIMIT_MEMLOCK`'s hard limit is normally gated on
`CAP_SYS_RESOURCE`. But `cilium/ebpf`'s `rlimit.RemoveMemlock()` first
probes whether the kernel accounts BPF memory via memcg instead (Linux
5.11+) — if that probe succeeds, it skips touching the rlimit entirely. The
probe itself needs `CAP_BPF`. That's why removing `cap_bpf` (not
`cap_sys_resource`) is what breaks `RemoveMemlock()`: without `cap_bpf` the
probe fails, the code falls back to actually raising the rlimit, and that
fallback path is what needs `cap_sys_resource`.

Practically: on a 5.11+ kernel, `cap_bpf` alone covers this path. On an
older kernel (5.8–5.10) that lacks memcg-based BPF accounting, tinytap
would additionally need `cap_sys_resource` to raise `RLIMIT_MEMLOCK`.

## Why TLS capture needs `cap_sys_admin`

The plaintext capture path only ever attaches to tracepoints and kernel
functions the kernel already exposes as attach points (`syscalls:sys_enter_*`
tracepoints, `tcp_sendmsg_locked` via fentry) — none of that requires
defining anything new, so `cap_perfmon` (added in 5.8 specifically to cover
this class of attach) is enough.

The TLS uprobes are different: a uprobe targets an arbitrary file+offset
inside a specific process's mapped library (`libssl.so.3` at whatever
address `SSL_set_fd` resolved to), which doesn't exist as a kernel-known
attach point ahead of time. Registering it calls `perf_event_open` against
the kernel's dynamic `uprobe` PMU — creating a brand-new trace point, not
attaching to an existing one. That's the same class of operation as writing
to the legacy `uprobe_events`/`kprobe_events` control files, and the kernel
gates it on `CAP_SYS_ADMIN` rather than `CAP_PERFMON`.

Practical effect: TLS capture needs `cap_sys_admin` for tinytap's entire
runtime whenever it's in use. `cap_sys_admin` is broad enough that this
materially weakens the "not full root" story for anyone who wants TLS
capture — running plaintext-only with the 3-capability set is meaningfully
more restricted than running with TLS enabled.

## Why not an in-process privilege drop

Dropping capabilities in-process after the initial probes attach might seem
appealing — once the ringbuf is open, does tinytap ever need to load a
program or attach a probe again? It does: TLS capture keeps discovering new
processes for tinytap's entire lifetime, attaching a fresh pair of uprobes
to each one the moment it's seen using libssl — each needing `cap_bpf`,
`cap_perfmon`, and `cap_sys_admin` again, at whatever point during the run
that process happens to first appear. Dropping capabilities right after the
initial load would silently break TLS capture for every process discovered
afterward, without stopping tinytap or making the regression obvious. Given
that, all the capabilities tinytap starts with need to stay live for the
whole process — `setcap` + non-root (above) is the supported way to run
with reduced privilege.

If TLS capture is ever made optional (a `--no-tls` flag, say), a scoped
in-process drop conditioned on that flag would become viable.

## Known gaps

- **Kernel version**: verified on Linux 6.17 (arm64) and 7.0.0 (amd64) — both well above the 5.8 floor. `CAP_PERFMON` as a distinct capability (split from `CAP_SYS_ADMIN`) only exists from 5.8 onward — the same floor tinytap already requires for `BPF_MAP_TYPE_RINGBUF`. Kernels between 5.8 and whatever version relaxed `BPF_PROG_TYPE_TRACING` attach checks may still need `cap_sys_admin` for the fentry step specifically; if so, that step degrades gracefully without blocking startup.

- **x86_64**: confirmed — the documented set holds. A full drop-one-at-a-time bisect on an amd64 host reproduced arm64's result step for step; the one arch-specific difference is the `sendfile` payload-capture kprobe's extra `cap_syslog` requirement.

- **Whether `cap_sys_admin` can be narrowed further for TLS** wasn't investigated beyond confirming it's sufficient.

The full drop-one-capability-at-a-time verification log (exact commands,
kernel versions, and error messages for both architectures) lives in
[`docs/capabilities.md`](https://github.com/shinagawa-web/tinytap/blob/main/docs/capabilities.md)
in the repo.
