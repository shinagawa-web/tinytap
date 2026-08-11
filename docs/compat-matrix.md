# tinytap Compatibility Matrix

Results from manual testing on real VMs. Every cell here is a real run, not an inference from kernel version. Untested cells are marked explicitly.

## How to read this table

| Column | Meaning |
|---|---|
| Distro | Distro release name — what the user knows they're running |
| Kernel | `uname -r` output observed during the test run |
| Arch | CPU architecture |
| BTF | `/sys/kernel/btf/vmlinux` present? |
| Loads | `tinytap` starts and all tracepoints attach |
| Plaintext | Plain HTTP capture works |
| TLS | libssl uprobe attaches and decrypts traffic |
| sendfile payload | `fentry/tcp_sendmsg_locked` kprobe attaches and captures payload bytes |
| Min caps (plain) | Minimal `setcap` set for plaintext capture |
| Min caps (TLS) | Minimal `setcap` set for TLS capture |
| Tested by | Issue reference |

**Status values**: ✓ tested-pass · ✗ tested-fail · — not tested

## Results

| Distro | Kernel | Arch | BTF | Loads | Plaintext | TLS | sendfile payload | Min caps (plain) | Min caps (TLS) | Tested by |
|---|---|---|---|---|---|---|---|---|---|---|
| Ubuntu 25.10 (dev VM) | 6.17.0-41-generic | arm64 | ✓ | ✓ | ✓ | ✓ | ✓ | `cap_dac_read_search,cap_perfmon,cap_bpf` | + `cap_sys_admin` | #157 |
| Ubuntu (CI, amd64) | 7.0.0 | amd64 | ✓ | ✓ | ✓ | ✓ | ✓ | `cap_dac_read_search,cap_perfmon,cap_bpf` | + `cap_sys_admin` | #194 |
| Fedora 43 | 6.17.1-300.fc43.aarch64 | arm64 | ✓ | ✓ | ✓ | ✓ | ✓ | `cap_dac_read_search,cap_perfmon,cap_bpf` | + `cap_sys_admin` | #213 |
| Debian 12 | 6.1.0-49-cloud-arm64 | arm64 | ✓ | ✓ | ✓ | ✓ | ✗ | `cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin` | same | #213 |
| AlmaLinux 9 | 5.14.0-687.5.3.el9_8.aarch64 | arm64 | ✓ | ✓ | ✓ | ✓ | ✗ | `cap_dac_read_search,cap_perfmon,cap_bpf` | same | #213 |
| Alpine 3.23 | 6.18.22-0-virt | arm64 | ✓ | ✓ | ✓ | ✓ | ✗ | `cap_dac_read_search,cap_perfmon,cap_bpf` | + `cap_sys_admin` | #213 |
| Ubuntu 20.04 | 5.4.0-216-generic | arm64 | ✓ | ✗ | ✗ | ✗ | ✗ | — | — | #213 |
| WSL2 | — | amd64 | — | — | — | — | — | — | — | untested |

### Ubuntu 20.04: below the kernel floor

Ubuntu 20.04 GA kernel (5.4.0) is below the 5.8 floor. Startup fails immediately:

```
kernel version: 5.4.0-216-generic (>= 5.8 required) — load objects: field HandleAccept4: program handle_accept4: map events: map create: invalid argument
```

`BPF_MAP_TYPE_RINGBUF` was added in kernel 5.8; the 5.4 kernel rejects the map creation with `invalid argument`. The error message correctly identifies the floor. The HWE kernel (5.15+) would work, but was not tested here — the GA kernel is what Ubuntu 20.04 ships by default.

### amd64 cap_syslog note

On amd64, the `fentry/tcp_sendmsg_locked` kprobe additionally needs `cap_syslog` for sendfile payload capture because x86_64 reads live kernel symbol addresses from `/proc/kallsyms` (subject to `kernel.kptr_restrict`). On arm64 the bases are compile-time constants so `cap_syslog` is never needed. See `docs/capabilities.md` for the full `kptr_restrict` sweep.

## Notes

### Fedora 43 — binary built on Ubuntu dev VM

The binary under test was built on the Ubuntu 25.10 dev VM (the canonical build environment) and copied to the Fedora VM. CO-RE handled the kernel difference at runtime. `make generate` is a CI step, not a per-distro requirement.

## Key findings

### #195: Is `cap_sys_admin` for TLS an Ubuntu-specific requirement?

**Refuted.** Fedora 43 (kernel 6.17.1, non-Ubuntu) also fails TLS uprobe attach without `cap_sys_admin`:

```
attach uprobe SSL_set_fd: creating perf_uprobe PMU: token ...: opening perf event: permission denied
```

This is identical to the Ubuntu error. The requirement is not Ubuntu-specific — `perf_event_open` against the dynamic uprobe PMU requires `CAP_SYS_ADMIN` on upstream 6.x kernels. AlmaLinux 9's RHEL 5.14 backport is the only tested exception where TLS uprobe attaches without it.

### sendfile tracepoint names

`sys_enter_sendfile64` / `sys_exit_sendfile64` are present on both Fedora 43 (kernel 6.17.1) and Debian 12 (kernel 6.1.0). The `sys_exit_sendfile` fallback is not needed on either kernel.

### arm64 sendfile kprobe: no `cap_syslog` needed

Confirmed on Fedora 43 (kernel 6.17.1): the `fentry/tcp_sendmsg_locked` kprobe attaches and captures sendfile payload bytes. This matches the arm64 result on Ubuntu (#157).

On Debian 12 (kernel 6.1.0) `fentry/tcp_sendmsg_locked` fails with `create raw tracepoint: not supported` — the program type is unavailable on this older kernel. sendfile events are captured (via the sendfile64 tracepoints) but carry no payload bytes.

### Debian 12: `perf_event_paranoid=3` raises the minimum cap set

Debian 12 ships with `kernel.perf_event_paranoid=3` — a Debian-specific extension beyond the standard 0/1/2 range that blocks `perf_event_open` even with `CAP_PERFMON`. As a result, **tracepoint attach requires `cap_sys_admin`** on Debian 12, even for plaintext-only capture. The minimum set is `cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin` for both plaintext and TLS.

### AlmaLinux 9: TLS works without `cap_sys_admin`

AlmaLinux 9 (kernel 5.14.0 RHEL backport) is the only tested distro where TLS uprobe attaches with base-3 caps only (`cap_dac_read_search,cap_perfmon,cap_bpf`) — no `cap_sys_admin` needed. The RHEL 5.14 kernel's perf_uprobe PMU is apparently more permissive than upstream 6.x kernels for dynamic uprobe registration.

### AlmaLinux 9: sendfile payload capture unavailable

`fentry/tcp_sendmsg_locked` attaches silently (no error) but captures 0 payload bytes. The kprobe detects sendfile calls by checking `msg->msg_flags & MSG_SPLICE_PAGES`, a flag added in upstream kernel 6.0. The RHEL 5.14 backport does not include it — `MSG_SPLICE_PAGES` is absent from system headers. sendfile events appear with correct metadata but carry no payload bytes.

### Alpine 3.23: static binary confirmed (#196)

`CGO_ENABLED=0` static binary built on the Ubuntu dev VM runs on Alpine 3.23 (musl libc) without modification. The glibc dynamic binary fails because `/lib/ld-linux-aarch64.so.1` is absent — only `/lib/ld-musl-aarch64.so.1` is available. The static build (`go build -ldflags='-extldflags -static'`) resolves this.

`fentry/tcp_sendmsg_locked` also fails on Alpine 3.23 (kernel 6.18.22-virt) with `create raw tracepoint: not supported` — the Alpine `virt` kernel does not have `BPF_PROG_TYPE_TRACING` fentry enabled.

### Debian 12: libssl execute bit

`/usr/lib/aarch64-linux-gnu/libssl.so.3` ships without the execute permission bit on Debian 12. tinytap's uprobe attach fails until `sudo chmod +x <path>` is run. This is the same issue documented for Ubuntu in `docs/capabilities.md`.
