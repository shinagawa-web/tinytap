---
title: Troubleshooting
weight: 9
---

# Troubleshooting

If it didn't work, run `tinytap doctor` first — read-only preflight checks
(kernel version, BTF availability, the required
[capabilities]({{< relref "running-without-root" >}}), syscall tracepoint
availability, a dry-run BPF load, and the host's libssl execute bit),
printed as a copy-paste-friendly report, without needing root or capabilities itself:

```bash
tinytap doctor
```

For example, on a host that hasn't been granted any capabilities yet:

```text
tinytap doctor — tinytap dev (commit none, built unknown)

[OK      ] kernel version               6.17.0-41-generic (>= 5.8 required)
[OK      ] kernel BTF                   /sys/kernel/btf/vmlinux present
[BLOCKING] cap_dac_read_search          missing
    Affects: Everything — needed to open /sys/kernel/tracing/events/syscalls/*/id to resolve tracepoint IDs.
    Fix:     sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog=eip <path-to-tinytap>   # adds cap_dac_read_search
[BLOCKING] cap_perfmon                  missing
    Affects: Everything — needed to attach the tracepoint/kprobe/fentry programs.
    Fix:     sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog=eip <path-to-tinytap>   # adds cap_perfmon
[BLOCKING] cap_bpf                      missing
    Affects: Everything — needed to load BPF programs and maps.
    Fix:     sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog=eip <path-to-tinytap>   # adds cap_bpf
[DEGRADED] cap_sys_admin                missing
    Affects: TLS capture only. Plaintext HTTP capture is unaffected.
    Fix:     sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog=eip <path-to-tinytap>   # adds cap_sys_admin
[OK      ] cap_syslog                   not needed on arm64
[INFO    ] perf_event_paranoid          4
[INFO    ] unprivileged_bpf_disabled    2
[INFO    ] RLIMIT_MEMLOCK               soft=8388608 hard=8388608
[OK      ] syscall tracepoints          all 16 present
[OK      ] architecture                 arm64 (sendfile kprobe + TLS uprobes supported)
[BLOCKING] BPF dry-run load             remove memlock: failed to set memlock rlimit: operation not permitted
    Affects: Everything — this is the first step tinytap's real startup performs.
    Fix:     run with the capabilities listed at https://shinagawa-web.github.io/tinytap/docs/running-without-root/, or as root
[OK      ] libssl (host)                /lib/aarch64-linux-gnu/libssl.so.3 executable

6 ok, 1 degraded, 4 blocking, 3 info
```

Granting the capabilities named in each `Fix` line (see
[Running Without Full Root]({{< relref "running-without-root" >}})) turns
every `BLOCKING`/`DEGRADED` line above into `OK`.

Each result is classified by what it actually costs: a blocking result
means tinytap can't run at all (e.g. a kernel below the 5.8 floor); a
degraded result means tinytap runs but one specific capability is lost
(e.g. no TLS capture without `cap_sys_admin`) — it's never printed as if
something were broken. `doctor` exits non-zero only when a blocking result
is present, so `tinytap doctor && tinytap` is a reasonable way to run it. A
normal startup failure also names the specific blocking cause instead of
only a raw error, pointing at `tinytap doctor` for the full picture.

## Common blocking causes

- **Kernel below 5.8** — tinytap's event transport (`BPF_MAP_TYPE_RINGBUF`) needs 5.8+. No workaround; upgrade the kernel or the VM image.

- **`libssl.so.3` missing the execute bit** — Debian/Ubuntu package it as mode `0644` by default, which the TLS uprobe attach requires. Until fixed, TLS capture silently finds nothing to hook (plaintext capture still works). One-time fix per host:

  ```bash
  ldconfig -p | grep libssl   # find the path
  sudo chmod +x <path>
  ```

  tinytap deliberately never does this itself.

- **Missing capabilities** — see [Running Without Full Root]({{< relref "running-without-root" >}}) for the exact `setcap` invocation and what each capability covers.
