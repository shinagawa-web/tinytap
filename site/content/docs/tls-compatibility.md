---
title: TLS Compatibility
weight: 9
---

# TLS Compatibility

Which TLS-terminating servers/clients tinytap can capture via the
`SSL_write`/`SSL_read`/`SSL_free` libssl uprobes, a separate mechanism from
the [Server Compatibility]({{< relref "server-compatibility" >}}) sample-cap
table. The uprobe reads the plaintext buffer directly (up to its own 4096 B
cap) before encryption or after decryption, rather than sampling wire bytes
off the ciphertext syscalls underneath.

## What's covered

| Server/client | fd-resolvable? | Result |
|---|---|---|
| Python `ssl`-wrapped `http.server` | ✅ calls `SSL_set_fd` | ✅ paired, decrypted correctly |
| nginx, Debian-based (`nginx:latest`) | ✅ calls `SSL_set_fd` directly (`ngx_ssl_create_connection()`) | ✅ paired, decrypted correctly |
| nginx, Alpine-based (`nginx:alpine`) | ✅ same as above | ✅ paired, decrypted correctly |
| curl | ❌ never calls `SSL_set_fd` (custom `BIO_METHOD` + `SSL_set_bio`) | ✅ paired via an SSL*-keyed stream instead of an fd-keyed one |
| Node.js (NodeSource / official / nvm builds) | ✅ calls `SSL_set_fd` (Node's own OpenSSL binding) | ✅ paired, decrypted correctly, via the executable fallback below, not a mapped `libssl.so` |

eBPF operates at the host kernel level, so this works the same whether the
TLS-terminating process is running natively or inside a Docker container.
A container's process is an ordinary host process under a different PID
namespace, with no container-aware code needed on tinytap's side.

See [Current Limitations]({{< relref "limitations" >}}) for how the
Node.js fallback and the Debian/Ubuntu `libssl.so.3` execute-bit gotcha
work, and [Troubleshooting]({{< relref "troubleshooting" >}}) for the fix.
