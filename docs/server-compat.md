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
| 🚫 | Worse than not captured: the exchange never pairs at all (parser stalls, ABANDONED on connection close) |
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
| Go `net/http` | #42 | — | — | — | — | |
| Node.js `http.createServer` | #43 | writev (1 call, 4 iovecs) | 🚫 | 🚫 | 🚫 | `createReadStream().pipe(res)` with no explicit `Content-Length` → chunked encoding; whole response (headers + chunk-size + chunk-data + terminator) goes out in one `writev`, but tinytap only samples iovec[0] — see notes |
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
- **Node.js (#43) — not a cap problem, a `writev` problem**: Node never uses `sendfile`, but `fs.createReadStream(file).pipe(res)` without an explicit `Content-Length` triggers chunked transfer-encoding, and the *entire* chunked response — status line, headers, chunk-size line, chunk data, and the `0\r\n\r\n` terminator — goes out as a **single `writev` call with 4 iovecs**. `bpf/tinytap.bpf.c`'s `read_iov` helper only ever samples `iovec[0]` (used for both `writev` and `readv`), regardless of how many iovecs the call carries or which one holds the actual body. Since the chunk-size/chunk-data/terminator live in iovecs 1–3, the HTTP parser's `stateNeedChunkSize` state never sees the bytes it needs to find chunk boundaries, so it never completes — the exchange sits pending until the connection closes and is reported as **ABANDONED ("peer closed")**, confirmed with `strace` + tinytap at all three body sizes. This is strictly worse than truncation: it isn't visible-but-cut-off, the request/response never pairs at all. Setting an explicit `Content-Length` before piping avoids chunked encoding (Node collapses to a 2-iovec `writev`: headers + body) and pairing succeeds again — but the body is still invisible, since it's iovec[1] and `read_iov` never samples past iovec[0]. Net effect: for any server/framework using multi-iovec `writev` (chunked responses are the common case — also flagged as "writev expected" for Axum, #104), the current writev probe can silently drop pairing entirely rather than just truncating the body. Worth a dedicated follow-up beyond #36 (which is only about the payload cap, not iovec selection).

## Reusable test fixtures

> Script and body-size files go here so #29 can wrap them with assertions.
