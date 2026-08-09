---
title: Current Limitations
weight: 11
---

# Current Limitations

- HTTP/1.1 only — no HTTP/2, gRPC, or other protocols yet

- TLS capture needs a dynamically linked `libssl.so`, so statically linked TLS stacks are invisible — that includes Go's `crypto/tls` and therefore Go-based proxies like Traefik and Caddy. Clients that hand OpenSSL a custom `BIO` instead of calling `SSL_set_fd` (e.g. curl) are captured and paired, but keyed on the `SSL*` pointer rather than a socket fd, so their exchanges are marked `[ssl-keyed, fd unverified]` — see [TLS Compatibility]({{< relref "compatibility/tls" >}})

- Debian/Ubuntu package `libssl.so.3` without the execute bit (mode `0644`), which the TLS uprobe attach requires — until fixed, TLS capture silently finds nothing to hook. One-time fix per host: find the path with `ldconfig -p | grep libssl`, then `sudo chmod +x <path>` (tinytap deliberately never does this itself — see [Troubleshooting]({{< relref "troubleshooting" >}}))

- Single host — no cross-container attribution or cross-service correlation yet

- Response bodies are sampled up to a fixed per-syscall cap, not captured in full — see [Server Compatibility]({{< relref "compatibility/server" >}}) for exactly how each server's syscall pattern affects this

- `sendfile`-based transfers only carry payload bytes on amd64/arm64 — other architectures see the exchange but not the sampled body

See [Compatibility]({{< relref "compatibility" >}}) for a server-by-server
breakdown of what's currently visible.
