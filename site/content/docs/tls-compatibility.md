---
title: TLS Compatibility
weight: 10
---

# TLS Compatibility

Which TLS-terminating servers/clients tinytap can capture via the
`SSL_write`/`SSL_read`/`SSL_free` libssl uprobes, a separate mechanism from
the [Server Compatibility]({{< relref "server-compatibility" >}}) sample-cap
table. The uprobe reads the plaintext buffer directly (up to its own 4096 B
cap) before encryption or after decryption, rather than sampling wire bytes
off the ciphertext syscalls underneath.

## What's covered

tinytap has been verified against Python `ssl`-wrapped `http.server`, nginx
(Debian-based and Alpine-based images), curl, and Node.js (NodeSource,
official, and nvm builds): TLS traffic decrypts and pairs correctly for
all of them. This only covers OpenSSL-based stacks; see
[Current Limitations]({{< relref "limitations" >}}) for what's not covered,
such as Go's `crypto/tls`.

eBPF operates at the host kernel level, so this works the same whether the
TLS-terminating process is running natively or inside a Docker container.
A container's process is an ordinary host process under a different PID
namespace, with no container-aware code needed on tinytap's side.

See [Current Limitations]({{< relref "limitations" >}}) for how the
Node.js fallback and the Debian/Ubuntu `libssl.so.3` execute-bit gotcha
work, and [Troubleshooting]({{< relref "troubleshooting" >}}) for the fix.
