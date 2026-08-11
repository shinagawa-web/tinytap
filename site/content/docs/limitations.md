---
title: Current Limitations
weight: 14
---

# Current Limitations

- HTTP/1.1 only, no HTTP/2, gRPC, or other protocols yet

- TLS capture needs OpenSSL to be reachable: either a dynamically linked `libssl.so`, or (confirmed for Node.js's official/NodeSource/nvm builds) an unstripped binary that statically bundles OpenSSL and still exports its symbols. Stacks that don't use OpenSSL at all remain invisible either way, which includes Go's `crypto/tls` and therefore Go-based proxies like Traefik and Caddy. Clients that hand OpenSSL a custom `BIO` instead of calling `SSL_set_fd` (e.g. curl) are captured and paired, but keyed on the `SSL*` pointer rather than a socket fd, so their exchanges are marked `[ssl-keyed, fd unverified]`. See [TLS Compatibility]({{< relref "tls-compatibility" >}})

- Debian/Ubuntu package `libssl.so.3` without the execute bit (mode `0644`), which the TLS uprobe attach requires. Until fixed, TLS capture silently finds nothing to hook. One-time fix per host: find the path with `ldconfig -p | grep libssl`, then `sudo chmod +x <path>` (tinytap deliberately never does this itself; see [Troubleshooting]({{< relref "troubleshooting" >}}))

- Single host, no cross-container attribution or cross-service correlation yet

- Response bodies are sampled up to a fixed per-syscall cap, not captured in full. See [Server Compatibility]({{< relref "server-compatibility" >}}) for exactly how each server's syscall pattern affects this

- `sendfile`-based transfers only carry payload bytes on amd64/arm64, and other architectures see the exchange but not the sampled body

See [Server Compatibility]({{< relref "server-compatibility" >}}) and
[TLS Compatibility]({{< relref "tls-compatibility" >}}) for a
server-by-server breakdown of what's currently visible.
