---
title: Troubleshooting
weight: 9
---

# Troubleshooting

If it didn't work, run `tinytap doctor` first — read-only preflight checks
(kernel version, BTF availability, the required
[capabilities]({{< relref "running-without-root" >}}), syscall tracepoint
availability, a dry-run BPF load, and the host's libssl execute bit),
printed as a copy-paste-friendly report, without needing root or
capabilities itself:

```bash
tinytap doctor
```

Each result is classified by what it actually costs: a **blocking** result
means tinytap can't run at all (e.g. a kernel below the 5.8 floor); a
**degraded** result means tinytap runs but one specific capability is lost
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
