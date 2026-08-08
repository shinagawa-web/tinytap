---
title: Where tinytap Runs
weight: 2
---

# Where tinytap Runs

**tinytap requires a Linux kernel.** It cannot run natively on macOS or
Windows, because eBPF is a Linux kernel technology. But that's less
restrictive than it sounds, because Linux kernels are everywhere:

| Where the user works | How tinytap runs there |
|---|---|
| Linux desktop / laptop / workstation | Native. Just run the binary. |
| Linux server (cloud VM, on-prem, dev box) | Native. SSH in, run it. |
| Mac (Intel or Apple Silicon) | Inside a Linux VM — Lima, Multipass, OrbStack, UTM, Docker Desktop's VM, etc. |
| Windows | Inside WSL2 (which is a real Linux kernel). |

This pattern — "Mac/Win developers run this through a Linux VM" — is the
standard for eBPF tooling in general (bpftrace, Cilium, etc.). tinytap is not
unusual here.

## Containers are friends, not enemies

A common question: "if my dev stack runs in Docker on my Mac, can tinytap see
inside the containers?"

**Yes.** A Docker container is just a process (or process tree) running on
the host's Linux kernel, isolated by namespaces and cgroups. eBPF programs
attach to kernel events — syscalls, kprobes, tracepoints — which fire for
*all* processes, container or not. So:

```text
Mac
└── Lima VM (Ubuntu)        ← tinytap runs here
    ├── tinytap (Go binary, sudo)
    └── Docker daemon
        ├── container: api-service
        ├── container: db
        └── container: cache
```

...tinytap, running in the VM as root, observes syscalls from the
containerized processes too — the same way it would for a process running
directly on the VM. This is the same reason `htop` on the host shows
container processes: they're all just kernel processes.

For the user, this means **tinytap doesn't need to be installed inside
containers**, doesn't need a sidecar, and doesn't require the application to
be rebuilt with anything. One install on the host is enough.

(Container-aware *attribution* — turning a PID into "this is the api-service
container" — is a planned feature, not yet built. The kernel sees the PIDs;
mapping them back to container names requires reading from
Docker/containerd. For now tinytap shows raw PIDs.)

## Requirements

- Linux kernel 5.8+ (tinytap's event transport is `BPF_MAP_TYPE_RINGBUF`, added in 5.8)

- macOS/Windows users run tinytap inside a Linux VM (Lima, WSL2, etc.) — there is no native macOS/Windows build and none is planned, since eBPF is Linux-only
