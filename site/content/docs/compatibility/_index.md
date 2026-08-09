---
title: Compatibility
weight: 6
---

# Compatibility

What's actually visible depends on which syscalls a server/client uses to
move bytes, and whether the traffic is plaintext or TLS-terminated — two
different capture mechanisms with different visibility models:

- [Server Compatibility]({{< relref "server" >}}) — plaintext HTTP, by server
- [TLS Compatibility]({{< relref "tls" >}}) — TLS-terminating servers/clients via the libssl uprobe
