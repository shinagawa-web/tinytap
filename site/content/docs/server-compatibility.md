---
title: Server Compatibility
weight: 6
---

# Server Compatibility

This covers plaintext HTTP only. For TLS-terminating servers (nginx, etc.)
captured via the `SSL_write`/`SSL_read` libssl uprobe, see
[TLS Compatibility]({{< relref "tls-compatibility" >}}) instead — it's a
different capture mechanism with a different visibility model, not just a
new row here.

## How to read this table

**Syscall** — the syscall(s) the server uses to send the HTTP response
body. Determines whether tinytap can see the body at all, and how much of
it.

**Pairing** — whether the exchange completes successfully (a status code is
shown) or is reported `ABANDONED`. A body being truncated by the sample cap
does not, by itself, cause an abandon — only specific framing bytes being
dropped can.

**Body visibility** — what the TUI shows for the response body:

| Symbol | Meaning |
|--------|---------|
| ✅ | Full body visible |
| ⚠️ | Visible but truncated at the 4096 B sample cap — exchange still pairs successfully |
| ❌ | Not captured (sendfile / splice path — body bypasses the BPF probe; a kprobe covers this on amd64 and arm64) |
| 🚫 | Exchange reported `ABANDONED` instead of pairing |
| — | Not yet tested |

**Body sizes / cases used in each run:**

| Label | Size | Rationale |
|-------|------|-----------|
| Small | < 1 KiB | Comfortably fits within the 4096 B sample cap — the "everything visible" baseline |
| Medium | ~8 KiB | Exceeds the cap by roughly 2x — tests truncated-but-paired behavior |
| Large | ~50 KiB | Forces the server to issue multiple write/chunk calls or use sendfile |
| Image | a real image file, `Content-Type: image/*` | Confirms the TUI shows the binary placeholder instead of a hex/decoded dump |

## Compatibility table

| Server | Syscall | Small | Medium | Large | Image | Notes |
|--------|---------|-------|--------|-------|-------|-------|
| Python `http.server` | sendto | ✅ | ⚠️ (4096 B / 8192 B) | ⚠️ (4096 B / 51200 B) | ✅ (placeholder) | Headers and body go out as two separate `sendto` calls; the body call is a single `sendto` regardless of size — no `sendfile`, no `writev`, no chunking |
| Go `net/http` | write (≤512 B body); write+sendfile (>512 B body) | ✅ 200/200 | ⚠️ arm64, 4096/8192 (kprobe cap) | ⚠️ arm64, 4096/51200 (kprobe cap) | ✅ placeholder | No `writev`/`sendmsg`, no chunked encoding, no `TCP_CORK` |
| Node.js `http.createServer` | writev (1 call, 4 iovecs) + write (chunk terminator) | ✅ 200/200 | ⚠️ 1024/8192 (writev-iovec budget) | ⚠️ 1024/51200 (same) | ✅ placeholder | `createReadStream().pipe(res)` with no `Content-Length` → chunked; pairs successfully, no `ABANDONED`; no `sendfile` anywhere |
| nginx (static, `sendfile on`) | writev (headers) + sendfile (body) | ✅ 200/200 | ⚠️ 4096/8192 (kprobe cap) | ⚠️ 4096/51200 (kprobe cap) | ✅ placeholder | Default nginx config; one `sendfile` call per response regardless of size |
| nginx (static, `sendfile off`) | writev, header+body coalesced into 1+ iovecs | ✅ 200/200 | ⚠️ 1024/8192 | ⚠️ 2048/51200 | ✅ placeholder | Body lives in `iovec[1+]` — the multi-iovec fix is what makes it visible at all |
| nginx (reverse proxy) | writev, multiple calls per response, 1–4 iovecs each | ✅ 200/200 | ⚠️ 1024/8192 | ⚠️ 6144/51200 | ✅ placeholder | `proxy_pass` never touches sendfile; body arrives via nginx's ~4 KiB proxy buffer, re-emitted as many small `writev` calls |
| Caddy | write (≤512 B body); write+sendfile (>512 B body) | ✅ 200/200 | ⚠️ arm64, 4096/8192 (kprobe cap) | ⚠️ arm64, 4096/51200 (kprobe cap) | ✅ placeholder | Same syscall shape as Go `net/http` — `file_server` uses the same `http.ServeContent` fast path |
| Bun.serve | read (file→buffer) + sendto (headers+body combined for small/medium, split for large) | ✅ 200/200 | ⚠️ 3978/8192 (4096 B cap shared with headers) | ⚠️ 4096/51200 (headers sent separately) | ✅ placeholder | No `sendfile` despite `Bun.file()` — reads the whole file into a userspace buffer |
| Uvicorn (ASGI) | sendto | ✅ 200/200 | ⚠️ (4096 B / 8192 B) | ⚠️ (4096 B / 51200 B) | ✅ (placeholder) | Same shape as Python `http.server` — no `writev`, `sendmsg`, `sendfile`, or chunked encoding |
| Gunicorn (WSGI) | sendto | ✅ 200/200 | ⚠️ (4096 B / 8192 B) | ⚠️ (4096 B / 51200 B) | ✅ (placeholder) | Sync worker uses `sendto` for both headers and body — same shape as Python `http.server`/Uvicorn |
| Axum (Rust / hyper) | writev (1 call, 2 iovecs: header + full body) | ✅ 200/200 | ⚠️ 1024/8192 (iovec[1] budget) | ⚠️ 1024/51200 (single writev call, no internal chunking) | ✅ placeholder | `Content-Length` always known (in-memory body, no streaming) → no chunked encoding, no `sendfile`; cleanest 2-iovec case observed |

## Cross-server summary

Across every server row in the table above, the outgoing syscall shape
falls into one of three groups — not about language or performance, but
about what each project treats as its core use case:

- **Plain `sendto`/`write`** — Python `http.server`, Uvicorn, Gunicorn, Bun.serve. Headers and body go out as ordinary buffered writes. No `sendfile`, `writev`, `sendmsg`, or chunked encoding anywhere in this group — visibility is governed purely by the flat 4096 B sample cap. These are all app-server-style runtimes whose response abstraction has no first-class notion of "this is a real file."

- **`sendfile`** — Go `net/http`, Caddy, nginx static with `sendfile on`. Static files are handed to the kernel via `sendfile(2)` once the body exceeds a small threshold. This is invisible to tinytap except where a kprobe (supported on both amd64 and arm64) samples a prefix — the one gap in this whole table that isn't just a matter of raising the sample cap. Some rows below were only exercised on arm64 so far — that's a testing-coverage gap, not an architecture limitation.

- **`writev`** — Node.js, nginx with `sendfile off` or as a reverse proxy, Axum/hyper. Headers and body (or several body chunks) travel as separate iovecs in one syscall. How *much* is visible is governed by a per-iovec sampling budget rather than the flat cap, and varies with how many iovecs/writev calls the body is split across.

A few points that generalize across rows:

- **The 4096 B cap is a per-syscall-buffer limit, not a body limit.** Most of the plain-`sendto` group shows a clean `4096/total` because headers and body are separate calls, but Bun.serve's medium case shows `3978/8192` because its headers shared the same `sendto` call as the body — the cap ate into the combined buffer.

- **Client-side (curl) byte counts are never a fixed constant**, unlike the server-side numbers in the plain-`sendto` and `sendfile` groups — they depend on however many `read`/`recvfrom` calls curl happens to make, each capped independently.

- **`sendfile` is the one true visibility gap in this table.** Every other truncation (the flat cap, the per-iovec budget) is a matter of tinytap sampling less than the full body; `sendfile`'s body bytes never reach a BPF-visible syscall at all except through the sendfile kprobe.

- **nginx's reverse-proxy row captures a two-hop artifact**: tinytap sees nginx's own outgoing request to the upstream server as a second, independent exchange (nginx acting as an HTTP/1.0 client) — worth knowing about when reading proxy rows, not a bug.
