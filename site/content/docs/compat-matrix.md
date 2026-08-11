---
title: Platform Support
weight: 10
---

# Platform Support

Which Linux distributions and kernel versions tinytap has been verified on.
Every row in the table below is a real test run. Untested combinations are not listed.

## arm64

| Distro | Kernel | Plaintext | TLS | Notes |
|---|---|---|---|---|
| Ubuntu 25.10 | 6.17.x | ✓ | ✓ | |
| Fedora 43 | 6.17.1 | ✓ | ✓ | |
| Debian 12 | 6.1.0 | ✓ | ✓ | sendfile body not captured; `cap_sys_admin` required even for plaintext |
| AlmaLinux 9 | 5.14.0 (RHEL) | ✓ | ✓ | sendfile body not captured |
| Alpine 3.23 | 6.18.22-virt | ✓ | ✓ | sendfile body not captured; static binary required |
| Ubuntu 20.04 (GA kernel) | 5.4.0 | ✗ | ✗ | kernel 5.8+ required |

## amd64

| Distro | Kernel | Plaintext | TLS | Notes |
|---|---|---|---|---|
| Ubuntu 26.04 | 7.0.0 | ✓ | ✓ | sendfile body requires `cap_syslog` (`kptr_restrict=1` blocks kprobe symbol lookup without it) |
| Ubuntu 24.04 | 6.17.0-azure | ✓ | ✓ | |
| Ubuntu 22.04 | 6.8.0-azure | ✓ | ✓ | |

"sendfile body not captured" means `GET /file.bin` returns status and size correctly but body bytes are 0. Only static file serving via `sendfile(2)` is affected. All other capture paths work normally. See [Server Compatibility]({{< relref "server-compatibility" >}}).

## Kernel floor: 5.8

tinytap requires Linux kernel 5.8 or later. Ubuntu 20.04's GA kernel (5.4.0) fails at startup:

```text
kernel version: 5.4.0-216-generic (>= 5.8 required) -- map create: invalid argument
```

`BPF_MAP_TYPE_RINGBUF`, the map type tinytap uses for the kernel-to-userspace
event pipe, was added in kernel 5.8. Ubuntu 20.04's HWE kernel (5.15+) works.

RHEL-family distros (AlmaLinux 9, Rocky Linux 9) report version numbers below
5.8 but backport the required BPF features. `BPF_MAP_TYPE_RINGBUF` is
present and tinytap loads correctly on AlmaLinux 9 despite the "5.14" label.

## Capability notes by distro

For the full capability story see [Running Without Root]({{< relref "running-without-root" >}}). Distro-specific differences:

**Debian 12:** ships with `kernel.perf_event_paranoid=3`, a non-standard
extension that blocks `perf_event_open` even for processes with `CAP_PERFMON`.
`cap_sys_admin` is required for tracepoint attach, so the minimum set for
plaintext capture is higher on Debian 12 than on other distros.

**AlmaLinux 9:** the RHEL backport kernel's perf_uprobe PMU is more
permissive than upstream 6.x. TLS uprobe attach works with the base-3
capability set, without `cap_sys_admin`. This is the only tested distro where
this holds.

**Alpine 3.23:** uses musl libc. The standard glibc-linked binary fails;
use a static build (`CGO_ENABLED=0 go build -ldflags='-extldflags -static'`).
Alpine's `virt` kernel config omits `BPF_PROG_TYPE_TRACING`, so
`fentry/tcp_sendmsg_locked` (the sendfile payload kprobe) is unavailable.

**TLS on Debian 12:** `libssl.so.3` ships without the execute permission
bit. Run `sudo chmod +x /usr/lib/aarch64-linux-gnu/libssl.so.3` before
starting tinytap. See [Troubleshooting]({{< relref "troubleshooting" >}}).
