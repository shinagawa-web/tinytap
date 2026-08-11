---
title: Server Compatibility
weight: 9
---

# Server Compatibility

Which syscall a plaintext HTTP server uses to send its response body
determines how much of it tinytap can see.

## Compatibility table

See [Cross-server summary](#cross-server-summary) below for what each
syscall means for visibility in practice.

| Server | Syscall | Notes |
|--------|---------|-------|
| Python `http.server` | `sendto` | Headers and body go out as separate `sendto` calls, no chunking |
| Go `net/http` | `write` / `sendfile` | `write` for small bodies, `sendfile` above ~512 B |
| Node.js `http.createServer` | `writev` | Chunked encoding when `Content-Length` is unknown |
| nginx (static, `sendfile on`) | `writev` + `sendfile` | Default nginx config |
| nginx (static, `sendfile off`) | `writev` | Body lives in `iovec[1+]` |
| nginx (reverse proxy) | `writev` | `proxy_pass` never touches `sendfile` |
| Caddy | `write` / `sendfile` | Same syscall shape as Go `net/http` |
| Bun.serve | `sendto` | No `sendfile` despite `Bun.file()` |
| Uvicorn (ASGI) | `sendto` | Same shape as Python `http.server` |
| Gunicorn (WSGI) | `sendto` | Same shape as Python `http.server`/Uvicorn |
| Axum (Rust / hyper) | `writev` | `Content-Length` always known, no chunking |

## Cross-server summary

Across every server row in the table above, the outgoing syscall shape
falls into one of three groups, not based on language or performance but
on what each project treats as its core use case:

- **Plain `sendto`/`write`**: Python `http.server`, Uvicorn, Gunicorn, Bun.serve. Headers and body go out as ordinary buffered writes. No `sendfile`, `writev`, `sendmsg`, or chunked encoding anywhere in this group. Visibility is governed purely by the flat 4096 B sample cap. These are all app-server-style runtimes whose response abstraction has no first-class notion of "this is a real file."

- **`sendfile`**: Go `net/http`, Caddy, nginx static with `sendfile on`. Static files are handed to the kernel via `sendfile(2)` once the body exceeds a small threshold. This is invisible to tinytap except where a kprobe (supported on both amd64 and arm64) samples a prefix: the one gap in this whole table that isn't just a matter of raising the sample cap. The Go `net/http` and Caddy rows above were only exercised on arm64 hardware so far. That's a testing-coverage gap, not an architecture limitation (the kprobe itself supports amd64 too).

- **`writev`**: Node.js, nginx with `sendfile off` or as a reverse proxy, Axum/hyper. Headers and body (or several body chunks) travel as separate iovecs in one syscall. How *much* is visible is governed by a per-iovec sampling budget rather than the flat cap, and varies with how many iovecs/writev calls the body is split across.

A few points that generalize across rows:

- **The 4096 B cap is a per-syscall-buffer limit, not a body limit.** When headers and body go out as separate `sendto`/`write` calls, the cap applies to the body alone. When a server combines them into a single call instead (Bun.serve does this), the cap eats into that combined buffer, so less of the body survives.

- **`sendfile` is the one true visibility gap in this table.** Every other truncation (the flat cap, the per-iovec budget) is a matter of tinytap sampling less than the full body; `sendfile`'s body bytes never reach a BPF-visible syscall at all except through the sendfile kprobe.

- **nginx's reverse-proxy row captures a two-hop artifact**: tinytap sees nginx's own outgoing request to the upstream server as a second, independent exchange (nginx acting as an HTTP/1.0 client), which is worth knowing about when reading proxy rows, not a bug.
