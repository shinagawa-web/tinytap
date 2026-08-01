# Running Without Full Root

> Part of v0.6.0 production readiness (#155). Documents the minimal Linux capability set tinytap needs, how it was verified empirically (#157), and what's still open.

## The minimal set

Plaintext HTTP capture (syscall tracepoints, ringbuf) needs three
capabilities on every architecture:

```bash
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf=eip ./tinytap
./tinytap   # no sudo
```

That's enough for the core capture path everywhere, and for the optional
`sendfile` payload-capture kprobe (`internal/loader/load_kprobe.go`) on
arm64 — but **not** for that same kprobe on x86_64, which additionally
needs `cap_syslog` (see the table below). Its failure degrades gracefully
either way (`tryAttachKprobe` logs and continues, sendfile events just
carry no payload bytes), so this only matters if you want full-fidelity
`sendfile` capture on x86_64:

```bash
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_syslog=eip ./tinytap
./tinytap   # no sudo
```

TLS capture (the `SSL_set_fd`/`SSL_write`/`SSL_read`/`SSL_free` libssl
uprobes, #146/#147/#173) needs `cap_sys_admin` on top of the base three —
see [Why TLS capture needs `cap_sys_admin`](#why-tls-capture-needs-cap_sys_admin)
below for why. Combined with the x86_64 kprobe requirement above, the set
`scripts/test-e2e.sh` actually runs under is:

```bash
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog=eip ./tinytap
./tinytap   # no sudo
```

**The binary must live on a filesystem mounted without `nosuid`.** The
kernel silently drops file capabilities (not just the setuid/setgid bits)
at exec time for binaries on a `nosuid` mount — `setcap` itself succeeds,
`getcap` still shows the capabilities, but the process starts with none of
them and fails as if `setcap` had never been run. `/tmp` is `nosuid` on this
dev VM (`findmnt -T /tmp`), which is exactly the mistake `scripts/test-e2e.sh`
and `scripts/test-e2e-tls-nginx.sh` made on the first pass of wiring this up
(both originally built the e2e binary into `/tmp`) — see `TT_BIN` in each
script for the fix (built into the repo root instead). Check with `findmnt -T
<path>` before relying on `setcap` anywhere new.

| Capability | What it's for | Confirmed by |
|---|---|---|
| `cap_bpf` | Loading BPF programs and maps (`BPF_PROG_LOAD`, `BPF_MAP_CREATE`) | Removing it made `rlimit.RemoveMemlock()` itself fail (see below) |
| `cap_perfmon` | Attaching the tracepoint/kprobe/fentry programs (`perf_event_open`-backed attach paths) | Removing it: `load program: operation not permitted (MEMLOCK may be too low...)` at `BPF_PROG_LOAD` |
| `cap_dac_read_search` | Opening `/sys/kernel/tracing/events/syscalls/*/id` to resolve tracepoint IDs — these files aren't world-readable | Removing it: `permission denied` opening `.../sys_enter_accept4/id` |
| `cap_sys_admin` | TLS only: dynamically registering a new uprobe (`SSL_set_fd` et al.) at an arbitrary file+offset | Removing it: `attach uprobe SSL_set_fd: creating perf_uprobe PMU: ... opening perf event: permission denied` — see below |
| `cap_syslog` | x86_64 only: reading real (non-zeroed) kernel symbol addresses from `/proc/kallsyms` for the `sendfile` payload-capture kprobe | CI (amd64, GitHub Actions runner): `populating kallsyms caches: ... symbol vmemmap_base: restricted by kernel.kptr_restrict and/or net.core.bpf_jit_harden sysctls (sendfile payload capture disabled)` without it; adding it made the CI `e2e` job pass |

`cap_sys_resource` is never needed (see below for why). `cap_net_admin`
(mentioned as a maybe in #157) isn't needed either — tinytap only attaches
syscall tracepoints, a kprobe, and libssl uprobes, none of which touch
netfilter/tc.

## How this was verified

A build of `cmd/tinytap` (arm64, kernel 6.17) had its file capabilities set via `setcap` and was run as a non-root user, dropping one capability at a time from the naive starting guess (`cap_dac_read_search,cap_sys_admin,cap_sys_resource,cap_perfmon,cap_bpf`) and checking whether it still attached cleanly:

1. Dropping `cap_sys_admin` — still attached cleanly at startup, including the optional `fentry/tcp_sendmsg_locked` kprobe (`internal/loader/load_kprobe.go`) that captures `sendfile` payload bytes. On this kernel, `BPF_PROG_TYPE_TRACING` attach didn't require it. (TLS uprobe attach — which happens later, dynamically, not at startup — turned out to be a different story; see below.)
2. Dropping `cap_dac_read_search` (in addition) — failed at tracepoint-ID lookup (see table above). Restored.
3. Dropping `cap_sys_resource` (in addition to no `cap_sys_admin`) — still attached cleanly.
4. Dropping `cap_perfmon` or `cap_bpf` individually (from the 3-capability set) — each broke a distinct step (see table above), confirming both are load-bearing.
5. Running the full `scripts/test-e2e.sh` suite (which also exercises the TLS scenario, unlike the manual check above) under the 3-capability set: every plaintext scenario passed, but the TLS scenario failed to attach its uprobe — see next section. Adding `cap_sys_admin` back made the whole suite pass, including TLS.
6. CI (GitHub Actions, amd64) surfaced a second, arch-specific gap: with the same 4-capability set that passed on arm64, the `e2e` job's sendfile-payload-kprobe assertion failed — `populating kallsyms caches: ... restricted by kernel.kptr_restrict` — because x86_64's kprobe path resolves live kernel symbol addresses from `/proc/kallsyms` (see `load_kprobe.go`'s doc comment: arm64 uses compile-time constants instead) and the runner's `kptr_restrict` hides real addresses without `CAP_SYSLOG`. Adding `cap_syslog` fixed it; CI is green with all five capabilities.

### Why `cap_sys_resource` turned out not to matter

`internal/loader/load.go` calls `rlimit.RemoveMemlock()` unconditionally before loading anything. Raising `RLIMIT_MEMLOCK`'s hard limit is normally gated on `CAP_SYS_RESOURCE`. But `cilium/ebpf`'s `rlimit.RemoveMemlock()` first probes whether the kernel accounts BPF memory via memcg instead (Linux 5.11+) — if that probe succeeds, it skips touching the rlimit entirely. The probe itself needs `CAP_BPF`. That's why removing `cap_bpf` (not `cap_sys_resource`) is what broke `RemoveMemlock()` in testing above: without `cap_bpf` the probe failed, the code fell back to actually raising the rlimit, and that fell back path is what needs `cap_sys_resource`.

Practically: on a 5.11+ kernel, `cap_bpf` alone covers this path. On an older kernel (5.8–5.10) that lacks memcg-based BPF accounting, tinytap would additionally need `cap_sys_resource` to raise `RLIMIT_MEMLOCK` — untested here since the dev VM runs 6.17.

### Why TLS capture needs `cap_sys_admin`

The plaintext capture path only ever attaches to tracepoints and kernel
functions the kernel already exposes as attach points (`syscalls:sys_enter_*`
tracepoints, `tcp_sendmsg_locked` via fentry) — none of that requires
defining anything new, so `cap_perfmon` (added in 5.8 specifically to cover
this class of attach) is enough.

`AttachSSLSetFd`/`AttachSSLReadWrite` (`internal/loader/load_uprobe.go`) are
different: a uprobe targets an arbitrary file+offset inside a specific
process's mapped library (`libssl.so.3` at whatever address `SSL_set_fd`
resolved to), which doesn't exist as a kernel-known attach point ahead of
time. `cilium/ebpf`'s `link.OpenExecutable(...).Uprobe(...)` creates it by
calling `perf_event_open` against the kernel's dynamic `uprobe` PMU
(`/sys/bus/event_source/devices/uprobe`) — registering a brand-new trace
point, not attaching to an existing one. That's the same class of operation
as writing to the legacy `uprobe_events`/`kprobe_events` control files, and
the kernel still gates it on `CAP_SYS_ADMIN` rather than `CAP_PERFMON`
(confirmed on 6.17 — see the table above for the exact permission-denied
error without it).

Practical effect: `sslWatcher`'s dynamic uprobe attach (see
[Why not an in-process privilege drop](#why-not-an-in-process-privilege-drop)) needs
`cap_sys_admin` for tinytap's entire runtime whenever TLS capture is in use.
`cap_sys_admin` is broad enough that this materially weakens the "not full
root" story for anyone who wants TLS capture — running plaintext-only with
the 3-capability set is meaningfully more restricted than running with TLS
enabled. If TLS capture is optional in the future (a `--no-tls` flag), the
3-capability set alone would be enough whenever it's off.

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
`BPF_PROG_LOAD` plus a new dynamic uprobe registration, needing `cap_bpf`,
`cap_perfmon`, and (per the previous section) `cap_sys_admin` again, at
whatever point during the run that process happens to first appear.

So dropping capabilities right after the initial `Load()` would silently
break TLS capture for every process discovered afterward — `maybeAttach`
only logs the resulting permission error
(`log.Printf("tls: attach SSL_set_fd for pid %d (%s): %v", ...)`), it
doesn't stop tinytap, so the regression wouldn't be obvious from the
outside. Given that, all the capabilities tinytap starts with need to stay
live for the whole process, and `setcap` + non-root (above) is the
supported way to run with reduced privilege — no in-process drop is
implemented. This is the "document why it can't" fallback #157 explicitly
allows when in-process dropping isn't practical.

If TLS capture is ever made optional (a `--no-tls` flag, say), a scoped
in-process drop conditioned on that flag would become viable and could be
revisited then.

## Known gaps

- **Kernel version**: this was verified on Linux 6.17. `CAP_PERFMON` as a distinct capability (split from `CAP_SYS_ADMIN`) only exists from 5.8 onward — the same floor tinytap already requires for `BPF_MAP_TYPE_RINGBUF` (see README's Requirements). Kernels between 5.8 and whatever version relaxed `BPF_PROG_TYPE_TRACING` attach checks may still need `cap_sys_admin` for the fentry step specifically; if so, that step degrades gracefully (`tryAttachKprobe` logs and continues without `sendfile` payload bytes — see its doc comment in `load_kprobe.go`), it does not block startup.
- **x86_64**: confirmed via CI (GitHub Actions runner, amd64, kernel version not controlled by us) — the base three capabilities plus `cap_sys_admin` (TLS) work the same as on arm64, but the `sendfile` payload-capture kprobe additionally needs `cap_syslog` there (see the table above and #194). Not yet re-run on a real amd64 dev box outside CI, so the exact `kptr_restrict` level that makes `cap_syslog` sufficient (vs. a stricter setting where nothing short of root would work) isn't independently confirmed.
- **Whether `cap_sys_admin` can be narrowed further for TLS** (e.g. some combination that doesn't include full `cap_sys_admin`) wasn't investigated beyond confirming it's sufficient — `cap_sys_admin` was tested as a single addition, not bisected further, since it's already the kernel's documented gate for dynamic uprobe/kprobe registration.
