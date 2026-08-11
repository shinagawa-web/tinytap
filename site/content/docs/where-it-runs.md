---
title: Where tinytap Runs
weight: 4
---

# Where tinytap Runs

**tinytap requires a Linux kernel.** It cannot run natively on macOS or
Windows, because eBPF is a Linux kernel technology. But that's less
restrictive than it sounds, because Linux kernels are everywhere:

| Where the user works | How tinytap runs there |
|---|---|
| Linux (desktop, laptop, workstation, or server) | Native. Just run the binary. |
| Mac (Intel or Apple Silicon) | Inside a Linux VM (Docker Desktop's VM, OrbStack, Lima, UTM, Multipass, etc.). |
| Windows | Inside WSL2 (which is a real Linux kernel). |

## Does tinytap see inside containers?

A common question: "if my dev stack runs in Docker on my Mac, can tinytap see
inside the containers?"

**Yes.** A Docker container is just a process (or process tree) running on
the host's Linux kernel, isolated by namespaces and cgroups. eBPF programs
attach to kernel events (syscalls, kprobes, tracepoints) which fire for
*all* processes, container or not. So:

```text
Mac
└── some Linux VM           ← tinytap runs here (Lima, OrbStack, Docker
    ├── tinytap (Go binary,    Desktop's own VM, etc. — any of them works,
    │   sudo)                 this isn't a Lima-specific trick)
    └── Docker daemon
        ├── container: api-service
        ├── container: db
        └── container: cache
```

...tinytap, running in the VM as root, observes syscalls from the
containerized processes too, the same way it would for a process running
directly on the VM. This is the same reason `htop` on the host shows container processes: they're all just kernel processes. The VM in the
diagram isn't special: it's whatever Linux kernel tinytap happens to be
running on, and Docker Desktop's own bundled VM (see the table above)
qualifies just as well as a VM you set up yourself.

For the user, this means tinytap doesn't need to be installed inside
containers, doesn't need a sidecar, and doesn't require the application to
be rebuilt with anything. One install on the host is enough.

(Container-aware *attribution*, turning a PID into "this is the api-service
container", is a planned feature, not yet built. The kernel sees the PIDs;
mapping them back to container names requires reading from
Docker/containerd. For now tinytap shows raw PIDs.)

### Can tinytap itself run inside a container?

Also yes, and this was verified directly, not just reasoned about. Running tinytap in a
plain (non-`--privileged`) container needs two things beyond the base
[capabilities]({{< relref "running-without-root" >}}):

```bash
docker run --cap-add=BPF --cap-add=PERFMON --cap-add=DAC_READ_SEARCH \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v $(pwd)/tinytap:/tinytap:ro \
  ubuntu:24.04 /tinytap --config /tinytap.toml
```

- The three `--cap-add` flags mirror the native `setcap` invocation in [Running Without Full Root]({{< relref "running-without-root" >}}) (add `SYS_ADMIN` for TLS capture, same as native).

- `/sys/kernel/tracing` (tracefs) isn't mounted into containers by default, and tinytap needs it to resolve syscall tracepoint IDs. Without this mount, `tinytap doctor` reports a blocking result ("syscall tracepoints missing"); with it, that check passes and capture works. No other bind mounts, `--privileged`, or seccomp changes were needed.

Once running, a containerized tinytap sees the whole host kernel, not
just its own container, the same host-wide visibility as running directly
on the VM. In this exact test, it captured the host's own `dockerd`
process's HTTP API traffic (`GET /v1.52/containers/.../json`, etc.) even
though `dockerd` was running outside the container entirely, confirming
the host-wide visibility is real, not just reasoned about.

## Requirements

- Linux kernel 5.8+ (tinytap's event transport is `BPF_MAP_TYPE_RINGBUF`, added in 5.8). This applies to the VM's kernel too when running under a VM, not just to native Linux hosts

- No native macOS/Windows build is planned, since eBPF is Linux-only
