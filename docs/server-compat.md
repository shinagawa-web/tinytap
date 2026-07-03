# Server Compatibility

> Part of v0.4.0 (#37). Manual exploration — each row is filled in by running tinytap against a real server and observing the captured traffic.

## How to read this table

**Syscall** — the syscall(s) the server uses to send the HTTP response body. Determines whether tinytap can see the body at all.

**Body visibility** — what the TUI shows for each body size:

| Symbol | Meaning |
|--------|---------|
| ✅ | Full body visible |
| ⚠️ | Visible but truncated at the 256 B BPF cap (#36) |
| ❌ | Not captured (sendfile / splice path — body bypasses the BPF probe) |
| — | Not yet tested |

**Body sizes used in each run:**

| Label | Size | Rationale |
|-------|------|-----------|
| Small | < 256 B | Fits within the BPF sample cap — the "everything visible" baseline |
| Medium | ~1 KiB | Exceeds the cap; tests truncation |
| Large | ~50 KiB | Forces the server to issue multiple write calls or use sendfile |

## Compatibility table

| Server | Issue | Syscall | Small | Medium | Large | Notes |
|--------|-------|---------|-------|--------|-------|-------|
| Python `http.server` | #41 | sendto | ✅ | ⚠️ (256 B / 1024 B) | ⚠️ (256 B / 51200 B) | Single `sendto` per body regardless of size — no `sendfile`, no chunking |
| Go `net/http` | #42 | write (small); write+sendfile (medium/large) | ✅ | ⚠️ arm64 (write prefix + 256 B kprobe) / ❌ x86_64 | ⚠️ arm64 (write prefix + 256 B kprobe) / ❌ x86_64 | `ServeContent`'s `io.ReaderFrom` fast path buffers a small prefix into one `write`, then hands the rest of the file to `sendfile`; on arm64 the `fentry/tcp_sendmsg_locked` kprobe (#68) captures the first 256 B of the sendfile transfer; on x86_64 sendfile-transferred bytes remain invisible; inline `w.Write` (`/hello`) never uses `sendfile` |
| Node.js `http.createServer` | #43 | — | — | — | — | |
| nginx (static, `sendfile on` — default) | #44 | `writev` (headers) + `sendfile` (body) | ✅ | ⚠️ arm64 (256 B kprobe) / ❌ x86_64 | ⚠️ arm64 (256 B kprobe) / ❌ x86_64 | Body goes out via a separate `sendfile` call, sampled by the #68 kprobe like Go's `ServeContent` path |
| nginx (static, `sendfile off`) | #44 | `writev` (headers+body, 2 iovecs) | ❌ (#111) | ❌ (#111) | ⚠️ partial, wrong offset (#111) | Body lands in `iovec[1]`, which the writev probe never samples (#111) — turning `sendfile` off makes the body *less* visible, not more |
| nginx (reverse proxy, `/proxy/`) | #44 | `writev` (headers+body, 2+ iovecs) | ❌ (#111) | ❌ (#111) | ❌ (#111), one incidental partial sample | Body is proxy-buffered and combined with headers into one `writev`; never touches `sendfile`, but hits the same #111 gap as static-off |
| Caddy | #45 | — | — | — | — | |
| Bun.serve | #46 | — | — | — | — | optional |
| Uvicorn (ASGI) | #102 | — | — | — | — | asyncio / libuv |
| Gunicorn (WSGI) | #103 | — | — | — | — | sync worker baseline |
| Axum (Rust / hyper) | #104 | — | — | — | — | writev expected |

## Cross-server summary

> To be written once #41–#44 are complete.

## Notes for #36 (lifting the 256 B BPF cap)

> Collect per-server surprises (TCP_CORK, MSG_MORE, kernel buffering, sendfile gaps) here once the rows are filled in.

- **Python `http.server` (#41)**: `BaseHTTPRequestHandler`/`SimpleHTTPRequestHandler` write headers and body as two separate `sendto` calls, and the body call is a single `sendto` regardless of size — confirmed with `strace` at 200 B, 1024 B, and 51200 B (no `sendfile`, no chunking into multiple writes even for the 50 KiB body). This means raising the BPF cap directly increases how much of *every* body is visible for this server; there's no per-chunk boundary to work around.
- **Go `net/http` (#42)**: `http.FileServer`/`ServeContent` on an `*os.File` takes the `io.ReaderFrom` fast path — confirmed with `strace`. For a 200 B body, headers + body fit in one `write(386)` and `sendfile` is never called. For 1024 B and 51200 B bodies, only a ~513 B prefix (headers + the first slice of the body) goes out via `write`; the remainder — 511 B and ~50.7 KiB respectively — goes out via a single `sendfile` call. On arm64 (Lima VM) the `fentry/tcp_sendmsg_locked` kprobe added in #68 intercepts the sendfile transfer and captures the first 256 B of the file content from the page cache, so the medium/large body is partially visible (write prefix + up to 256 B kprobe sample). On x86_64 the kprobe is not yet implemented (#112) and the sendfile bytes remain invisible. The inline `w.Write` handler (`/hello`) never takes this path — always a plain `write`, always visible up to the cap.
- **nginx (#44)**: confirmed with `strace -f -e trace=write,sendto,sendmsg,writev,sendfile,setsockopt` against `nginx 1.28.0`, for `sendfile on|off` (default `on`), `tcp_nopush on|off`, and a reverse-proxy `location` in the same config (default nginx never sends headers and body in separate syscalls — it always coalesces or offloads):
  - **`sendfile on` (the nginx default)**: headers go out via a single-iovec `writev`, then the body via its own `sendfile(out_fd, in_fd, &offset, count)` call — one `sendfile` call per response regardless of size (200 B, 1024 B, and 51200 B bodies each produced exactly one `sendfile`, no chunking). This is the same shape as Go's `ServeContent` path, so the #68 `fentry/tcp_sendmsg_locked` kprobe samples up to 256 B of it on arm64; on x86_64 (#112) it's invisible.
  - **`sendfile off`**: the surprising result. nginx does *not* fall back to a `write`-then-`write` pair like Python's `http.server`. Instead it coalesces headers and body into **one `writev` call with 2 iovecs** — `iovec[0]` is the header block, `iovec[1]` is the body. tinytap's writev probe (`read_iov` in `bpf/tinytap.bpf.c`) only ever samples `iovec[0]` (#111) — verified directly in the source, not just inferred from behavior — so **the entire body is invisible**, not truncated, for the 200 B and 1024 B cases. Turning `sendfile` off to "fix" the sendfile blind spot makes nginx strictly *worse* to observe, because it swaps a sampled-but-capped body (via the #68 kprobe) for a completely unsampled one (via #111). For the 51200 B body, nginx splits the transfer into two `writev` calls — the first still pairs headers with a 32768 B body prefix (2 iovecs, prefix invisible per #111), but the second call carries only the remaining 18432 B as a lone iovec, which *is* `iovec[0]` of that call and gets a 256 B sample — from byte offset 32768 of the file, not the start. So the large case is "partially visible" only by accident of chunk alignment, not because more of the response was sampled.
  - **Reverse proxy (`/proxy/`, `proxy_pass` to a backend)**: never touches `sendfile` — the body is proxy-buffered, so it always goes out via `writev`, coalesced with headers exactly like the `sendfile off` static case, and hits the identical #111 gap. Small and medium bodies (200 B, 1024 B) are 2-iovec `writev` calls, so the body is entirely invisible. The 51200 B body is split across six `writev` calls following nginx's proxy buffer size (mostly 4096 B chunks, plus one 3907 B chunk alongside the 197 B header in the first call — 197 + 3907 + 4096 = 8200 B); five of those six calls have 2+ iovecs (invisible per #111), but one incidental call happens to carry a single 4096 B chunk alone as its only iovec, giving a 256 B sample from the middle of the file — again not correlated with the start of the response, and not something a viewer could rely on.
  - **`tcp_nopush on`** (only meaningful with `sendfile on`): wraps the header `writev` + body `sendfile` pair in `setsockopt(TCP_CORK, 1)` / `setsockopt(TCP_CORK, 0)`, confirmed in the strace log. This is a kernel-level packet-coalescing hint (fewer TCP segments on the wire) and does not change the syscall shape tinytap observes — same `writev`-then-`sendfile` sequence, same sample behavior as plain `sendfile on`.
  - **Net effect**: for nginx specifically, the sub-issue's original premise — "sendfile blocks the static path, but the reverse-proxy path is visible" — turned out to be backwards. The reverse-proxy path is *not* reliably visible; it hits the same iovec[0]-only gap (#111) as the sendfile-off static path. The one case with any real visibility is the nginx *default* (`sendfile on`), via the #68 kprobe. Fixing #111 (sampling more than `iovec[0]`, or at least the largest iovec) would fix the static-off and reverse-proxy cases; fixing #36 (raising the 256 B cap) only helps the already-partially-visible `sendfile on` case.

## Reusable test fixtures

> Script and body-size files go here so #29 can wrap them with assertions.
