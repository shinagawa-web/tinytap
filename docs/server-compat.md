# Server Compatibility

> Part of v0.4.0 (#37). Manual exploration — each row is filled in by running tinytap against a real server and observing the captured traffic.
>
> Verification criteria reset (this revision) now that #36 (256 B → 4096 B payload cap), #111 (writev/readv multi-iovec sampling), #116 (chunked CRLF-drop no longer abandons), and #117 (binary body TUI placeholder) have all landed. Every server row below — including ones previously filled in — starts over from scratch against the current criteria; nothing from an earlier revision of this doc should be assumed to still hold.

## How to read this table

**Syscall** — the syscall(s) the server uses to send the HTTP response body. Determines whether tinytap can see the body at all, and whether the writev/readv multi-iovec fix (#111) or the still-open sendmsg/recvmsg multi-iovec gap (#113) is in play.

**Pairing** — whether the exchange completes successfully (a status code is shown) or is reported `ABANDONED`. A body being truncated by the sample cap does not, by itself, cause an abandon (#35/#36) — only specific framing bytes being dropped can (#116 fixed the chunked CRLF case; #122 tracks the still-open chunked trailer case).

**Body visibility** — what the TUI shows for the response body:

| Symbol | Meaning |
|--------|---------|
| ✅ | Full body visible |
| ⚠️ | Visible but truncated at the 4096 B BPF cap (#36) — exchange still pairs successfully |
| ❌ | Not captured (sendfile / splice path — body bypasses the BPF probe; the #68 kprobe covers this on arm64 only today, #112 tracks x86_64) |
| 🚫 | Exchange reported `ABANDONED` instead of pairing |
| — | Not yet tested |

**Body sizes / cases used in each run:**

| Label | Size | Rationale |
|-------|------|-----------|
| Small | < 1 KiB | Comfortably fits within the 4096 B sample cap — the "everything visible" baseline |
| Medium | ~8 KiB | Exceeds the cap by roughly 2x — tests truncated-but-paired behavior |
| Large | ~50 KiB | Forces the server to issue multiple write/chunk calls or use sendfile |
| Image | a real image file, `Content-Type: image/*` | Confirms the TUI shows the binary placeholder (#117) instead of a hex/decoded dump — a display check, not a capture-visibility check |

**Additional things to note per server, beyond the visibility table:**

- Does `writev`/`readv` carry the body in a later iovec (not `iovec[0]`)? If so, #111's fix is what makes it visible at all — worth calling out explicitly since it's easy to misattribute visibility to the cap alone.
- Does `sendmsg`/`recvmsg` appear, and with more than one iovec? If so, flag it as affected by #113 (not yet fixed) — body living in `iovec[1+]` of a `sendmsg`/`recvmsg` call is invisible regardless of the cap.
- Is `Transfer-Encoding: chunked` used? Confirm the exchange pairs successfully (#116) rather than `ABANDONED`. If the server sends trailer fields (uncommon), note whether #122's still-open gap is hit.
- Is `sendfile`(2) used for static files? Confirm the arm64 kprobe (#68) still samples a prefix; note that x86_64 has no equivalent yet (#112).
- Any `TCP_CORK` / `MSG_MORE` / kernel buffering surprises worth recording for #36's design history.

## Compatibility table

| Server | Issue | Syscall | Small | Medium | Large | Image | Notes |
|--------|-------|---------|-------|--------|-------|-------|-------|
| Python `http.server` | #41 | — | — | — | — | — | |
| Go `net/http` | #42 | write (≤512 B body); write+sendfile (>512 B body) | ✅ | ⚠️ arm64 (512 B write prefix + 4096 B kprobe sample) / ❌ x86_64 | ⚠️ arm64 (512 B write prefix + 4096 B kprobe sample) / ❌ x86_64 | ✅ (placeholder) | No `writev`/`sendmsg`, no chunked encoding, no `TCP_CORK` — #111/#113/#116/#122 don't apply to this server |
| Node.js `http.createServer` | #43 | — | — | — | — | — | |
| nginx (static + proxy) | #44 | — | — | — | — | — | sendfile expected for static files |
| Caddy | #45 | — | — | — | — | — | |
| Bun.serve | #46 | — | — | — | — | — | optional |
| Uvicorn (ASGI) | #102 | — | — | — | — | — | asyncio / libuv |
| Gunicorn (WSGI) | #103 | — | — | — | — | — | sync worker baseline |
| Axum (Rust / hyper) | #104 | — | — | — | — | — | writev expected |

## Cross-server summary

> To be written once the main servers are re-verified against the current criteria.

## Notes for #36 / #111 / #113 / #116 / #122 (per-server surprises)

> Collect per-server surprises (TCP_CORK, MSG_MORE, kernel buffering, sendfile gaps, multi-iovec placement) here as rows are filled in.

- **Go `net/http` (#42)**: confirmed with `strace -f -e trace=network,write,writev,sendto,sendmsg,sendfile` against a minimal server (`w.Write` for `/hello`, `http.FileServer` for everything else) serving 200 B, 8192 B, 51200 B, and a 68 B PNG (`Content-Type: image/png`).
  - **≤512 B bodies (small.txt, image.png)**: `ServeContent`'s `io.ReaderFrom` fast path bundles the whole body into the same buffer as the response headers, so it goes out as a single `write` (386 B and 237 B respectively) — never touches `sendfile`. Fully visible, well within the 4096 B cap. The image response correctly carries `Content-Type: image/png`, so the TUI shows the #117 binary placeholder instead of a hex/decoded dump for this row.
  - **>512 B bodies (medium.txt, large.txt)**: the fast path always writes the headers plus exactly the *first 512 B* of the body in one `write` call (699 B and 700 B on the wire, i.e. ~187–188 B of headers + 512 B of body), then hands the entire remainder to a single `sendfile` call (7680 B for the 8192 B body, 50688 B for the 51200 B body — in both cases `total − 512`). This 512 B split happens regardless of body size or whether `Content-Type` was already resolved by the file extension, so it looks like the same buffer `ServeContent` always primes before deciding on the sendfile path. On arm64 (this Lima VM) the `fentry/tcp_sendmsg_locked` kprobe (#68) samples up to 4096 B of the sendfile transfer from the page cache, so the total visible fraction is the 512 B write prefix plus up to 4096 B from the kprobe (4608 of 8192 B for medium; 4608 of 51200 B for large) — truncated but paired successfully, since an explicit `Content-Length` is always set and draining is pure wire-byte accounting (no abandon risk per #116's non-chunked path). On x86_64 the kprobe isn't implemented yet (#112), so only the 512 B write prefix is visible and the rest of the body is invisible.
  - **Net effect**: none of `writev`, `sendmsg`, or chunked `Transfer-Encoding` appear anywhere in this server's default paths, so #111, #113, #116, and #122 are all non-issues for Go's `net/http` — the only capture gap here is the sendfile path itself (#36's cap plus #112's missing x86_64 kprobe). No `TCP_CORK`/`MSG_MORE` — only the usual `TCP_NODELAY` + keepalive `setsockopt`s.

## Reusable test fixtures

> Script and body-size files go here so #29 can wrap them with assertions.
