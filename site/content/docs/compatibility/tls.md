---
title: TLS Compatibility
weight: 2
---

# TLS Compatibility

Which TLS-terminating servers/clients tinytap can capture via the
`SSL_write`/`SSL_read`/`SSL_free` libssl uprobes.

## Why this is separate from server compatibility

[Server Compatibility]({{< relref "server" >}})'s table measures how many
**wire bytes** of a plaintext body survive tinytap's per-syscall sample cap.
That question doesn't apply to TLS capture: the uprobe reads the **full
plaintext buffer** directly from the `SSL_write`/`SSL_read` call's
arguments (up to a separate 4096 B cap), before encryption or after
decryption — however many ciphertext syscalls happen underneath is
invisible to this capture path entirely. Reusing the same table would
conflate two unrelated capture mechanisms under the same columns.

## What's covered

| Server/client | fd-resolvable? | Result |
|---|---|---|
| Python `ssl`-wrapped `http.server` | ✅ calls `SSL_set_fd` | ✅ paired, decrypted correctly |
| nginx, Debian-based (`nginx:latest`) | ✅ calls `SSL_set_fd` directly (`ngx_ssl_create_connection()`) | ✅ paired, decrypted correctly |
| nginx, Alpine-based (`nginx:alpine`) | ✅ same as above | ✅ paired, decrypted correctly |
| curl | ❌ never calls `SSL_set_fd` (custom `BIO_METHOD` + `SSL_set_bio`) | ✅ paired via an SSL*-keyed stream instead of an fd-keyed one |

eBPF operates at the host kernel level, so this works the same whether the
TLS-terminating process is running natively or inside a Docker container —
a container's process is an ordinary host process under a different PID
namespace, with no container-aware code needed on tinytap's side.

One practical gotcha worth knowing up front: Debian/Ubuntu ships
`libssl.so.3` without the execute bit by default, which the uprobe attach
requires — see [Current Limitations]({{< relref "limitations" >}}) and
[Troubleshooting]({{< relref "troubleshooting" >}}) for the fix.
