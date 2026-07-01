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
| nginx (static + proxy) | #44 | — | — | — | — | sendfile expected for static files |
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

## Reusable test fixtures

> Script and body-size files go here so #29 can wrap them with assertions.
