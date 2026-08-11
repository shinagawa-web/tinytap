---
title: Platform Support
weight: 10
---

# Platform Support

Which Linux distributions and kernel versions tinytap has been verified on.
Every row in the table below is a real test run — cells marked **—** are
untested, not inferred from the kernel version.

## Tested matrix

| Distro | Kernel | Arch | Loads | Plaintext | TLS | sendfile payload | Min caps (plain) | Min caps (TLS) |
|---|---|---|---|---|---|---|---|---|
| Ubuntu 25.10 | 6.17.x | arm64 | ✓ | ✓ | ✓ | ✓ | base-3 | + `cap_sys_admin` |
| Ubuntu 24.04 | — | amd64 | — | — | — | — | — | — |
| Ubuntu 22.04 | 6.8.0-azure (CI) | amd64 | ✓ | ✓ | ✓ | ✓ | base-3 | + `cap_sys_admin` |
| Ubuntu 20.04 (GA kernel) | 5.4.0 | arm64 | ✗ | ✗ | ✗ | ✗ | — | — |
| Fedora 43 | 6.17.1 | arm64 | ✓ | ✓ | ✓ | ✓ | base-3 | + `cap_sys_admin` |
| Debian 12 | 6.1.0 | arm64 | ✓ | ✓ | ✓ | ✗ | base-3 + `cap_sys_admin` | same |
| AlmaLinux 9 | 5.14.0 (RHEL) | arm64 | ✓ | ✓ | ✓ | ✗ | base-3 | same |
| Alpine 3.23 | 6.18.22-virt | arm64 | ✓ | ✓ | ✓ | ✗ | base-3 | + `cap_sys_admin` |
| WSL2 | — | amd64 | — | — | — | — | — | — |

**base-3** = `cap_dac_read_search,cap_perfmon,cap_bpf`

**sendfile payload ✗** means `GET /file.bin → 200 0/52000B`: the request is captured with correct status and size, but body bytes are 0. Only static file serving via `sendfile(2)` is affected — all other capture paths work normally. See [Server Compatibility]({{< relref "server-compatibility" >}}).

## Kernel floor: 5.8

tinytap requires **Linux kernel 5.8 or later**. Ubuntu 20.04's GA kernel
(5.4.0) fails at startup:

```
kernel version: 5.4.0-216-generic (>= 5.8 required) — map create: invalid argument
```

`BPF_MAP_TYPE_RINGBUF`, the map type tinytap uses for the kernel→userspace
event pipe, was added in kernel 5.8. Ubuntu 20.04's HWE kernel (5.15+) works.

RHEL-family distros (AlmaLinux 9, Rocky Linux 9) report version numbers below
5.8 but backport the required BPF features — `BPF_MAP_TYPE_RINGBUF` is
present and tinytap loads correctly on AlmaLinux 9 despite the "5.14" label.

## Capability notes by distro

For the full capability story see [Running Without Root]({{< relref "running-without-root" >}}). Distro-specific differences:

**Debian 12** — ships with `kernel.perf_event_paranoid=3`, a non-standard
extension that blocks `perf_event_open` even for processes with `CAP_PERFMON`.
`cap_sys_admin` is required for tracepoint attach, so the minimum set for
plaintext capture is higher on Debian 12 than on other distros.

**AlmaLinux 9** — the RHEL backport kernel's perf_uprobe PMU is more
permissive than upstream 6.x: TLS uprobe attach works with the base-3
capability set, without `cap_sys_admin`. This is the only tested distro where
this holds.

**Alpine 3.23** — uses musl libc. The standard glibc-linked binary fails;
use a static build (`CGO_ENABLED=0 go build -ldflags='-extldflags -static'`).
Alpine's `virt` kernel config omits `BPF_PROG_TYPE_TRACING`, so
`fentry/tcp_sendmsg_locked` (the sendfile payload kprobe) is unavailable.

**TLS on Debian 12** — `libssl.so.3` ships without the execute permission
bit. Run `sudo chmod +x /usr/lib/aarch64-linux-gnu/libssl.so.3` before
starting tinytap. See [Troubleshooting]({{< relref "troubleshooting" >}}).
