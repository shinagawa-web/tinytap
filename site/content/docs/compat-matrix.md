---
title: Platform Support
weight: 5
---

# Platform Support

Results from manual testing on real VMs (#213). Every cell is a real run — untested cells are marked explicitly rather than inferred from kernel version.

## Tested matrix

| Distro | Kernel | Arch | BTF | Loads | Plaintext | TLS | sendfile payload | Min caps (plain) | Min caps (TLS) |
|---|---|---|---|---|---|---|---|---|---|
| Ubuntu 25.10 | 6.17.x | arm64 | ✓ | ✓ | ✓ | ✓ | ✓ | base-3 | + `cap_sys_admin` |
| Ubuntu 24.04 | — | amd64 | — | — | — | — | — | — | — |
| Ubuntu 22.04 (CI) | 6.8.0-azure | amd64 | ✓ | ✓ | ✓ | ✓ | ✓ | base-3 | + `cap_sys_admin` |
| Ubuntu (amd64 dev VM) | 7.0.0 | amd64 | ✓ | ✓ | ✓ | ✓ | ✓ | base-3 | + `cap_sys_admin` |
| Fedora 43 | 6.17.1 | arm64 | ✓ | ✓ | ✓ | ✓ | ✓ | base-3 | + `cap_sys_admin` |
| Debian 12 | 6.1.0 | arm64 | ✓ | ✓ | ✓ | ✓ | ✗ | base-3 + `cap_sys_admin` | same |
| AlmaLinux 9 | 5.14.0 (RHEL) | arm64 | ✓ | ✓ | ✓ | ✓ | ✗ | base-3 | same |
| Alpine 3.23 | 6.18.22-virt | arm64 | ✓ | ✓ | ✓ | ✓ | ✗ | base-3 | + `cap_sys_admin` |
| Ubuntu 20.04 (GA) | 5.4.0 | arm64 | ✓ | ✗ | ✗ | ✗ | ✗ | — | — |
| WSL2 | — | amd64 | — | — | — | — | — | — | — |

**base-3** = `cap_dac_read_search,cap_perfmon,cap_bpf`

**Status**: ✓ tested-pass · ✗ tested-fail · — untested

> **sendfile payload ✗**: request metadata is captured correctly (`GET /file 200 0/52000B`) but body bytes are 0. This only affects static file serving via `sendfile(2)` — all other capture paths work normally.

## Key findings

### Kernel floor 5.8 confirmed

Ubuntu 20.04 GA kernel (5.4.0) fails at startup:

```
kernel version: 5.4.0-216-generic (>= 5.8 required) — map create: invalid argument
```

`BPF_MAP_TYPE_RINGBUF` was added in kernel 5.8; the 5.4 kernel rejects the map creation outright. The floor is now a tested statement, not a reasoned one.

### AlmaLinux 9 (RHEL 5.14 backport): ringbuf works, TLS needs no `cap_sys_admin`

Despite the "5.14" version number, `BPF_MAP_TYPE_RINGBUF` loads — RHEL has backported it. The `5.8+` floor holds.

AlmaLinux 9 is the only tested distro where TLS uprobe attaches without `cap_sys_admin`. The RHEL backport kernel's perf_uprobe PMU is more permissive than upstream 6.x.

### Debian 12: `perf_event_paranoid=3` raises the minimum set

Debian ships `kernel.perf_event_paranoid=3` — a Debian-specific extension that blocks `perf_event_open` even with `CAP_PERFMON`. As a result, `cap_sys_admin` is required on Debian 12 even for plaintext-only capture.

### sendfile payload: unavailable on 3 of 5 non-Ubuntu distros

- **Debian 12** (kernel 6.1), **Alpine 3.23** (virt kernel): `BPF_PROG_TYPE_TRACING` fentry not available in these kernel builds — `fentry/tcp_sendmsg_locked` fails with `create raw tracepoint: not supported`.
- **AlmaLinux 9** (RHEL 5.14): kprobe attaches but captures 0 bytes — `MSG_SPLICE_PAGES` (the flag tinytap checks to detect sendfile calls) was added upstream in kernel 6.0 and is absent from this backport.

### Alpine 3.23: static binary required

Alpine uses musl libc; the standard glibc-linked binary fails. A `CGO_ENABLED=0` static build runs without modification, confirming the assumption from #196.

### `cap_sys_admin` for TLS: not Ubuntu-specific

Fedora 43 (kernel 6.17.1) and Alpine 3.23 (kernel 6.18) both require `cap_sys_admin` for TLS uprobe attach, with the same error as Ubuntu:

```
attach uprobe SSL_set_fd: creating perf_uprobe PMU: opening perf event: permission denied
```

The requirement is standard upstream kernel behavior for dynamic uprobe registration, not an Ubuntu-specific patch.
