---
title: TLS Compatibility
weight: 9
---

# TLS Compatibility

Which TLS-terminating servers/clients tinytap can capture via the
`SSL_write`/`SSL_read`/`SSL_free` libssl uprobes.

## Why this is separate from server compatibility

[Server Compatibility]({{< relref "server-compatibility" >}})'s table measures how many
wire bytes of a plaintext body survive tinytap's per-syscall sample cap.
That question doesn't apply to TLS capture: the uprobe reads the full
plaintext buffer directly from the `SSL_write`/`SSL_read` call's
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
| Node.js (NodeSource / official / nvm builds) | ✅ calls `SSL_set_fd` (Node's own OpenSSL binding) | ✅ paired, decrypted correctly — via the executable fallback below, not a mapped `libssl.so` |

eBPF operates at the host kernel level, so this works the same whether the
TLS-terminating process is running natively or inside a Docker container —
a container's process is an ordinary host process under a different PID
namespace, with no container-aware code needed on tinytap's side.

## Node.js: capturing a statically-linked OpenSSL

Every other row above has the traced process load OpenSSL as a separate
`libssl.so*` mapping, which tinytap locates by scanning the process's
memory maps. Node.js doesn't fit that shape — its official, NodeSource, and
nvm builds statically bundle OpenSSL, so a Node.js process never has a
`libssl.so*` mapping at all. Those same builds ship unstripped, though,
exporting `SSL_read`/`SSL_write`/`SSL_set_fd`/`SSL_free` from the `node`
binary itself — so tinytap falls back to the process's own executable once
the library scan comes up empty, and attaches there instead.

Distro-packaged Node.js (Debian/Ubuntu/Alpine's own `nodejs`/`node`
packages via `apt`/`apk`) dynamically links the system `libssl.so`
instead, so those installs already work via the normal path above and
never need the fallback.

One practical gotcha worth knowing up front: Debian/Ubuntu ships
`libssl.so.3` without the execute bit by default, which the uprobe attach
requires — see [Current Limitations]({{< relref "limitations" >}}) and
[Troubleshooting]({{< relref "troubleshooting" >}}) for the fix.
