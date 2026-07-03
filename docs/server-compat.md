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
| Go `net/http` | #42 | write (≤512 B body); write+sendfile (>512 B body) | ✅ 200/200 | ⚠️ arm64, 4096/8192 (kprobe cap) — x86_64 not run this pass | ⚠️ arm64, 4096/51200 (kprobe cap) — x86_64 not run this pass | ✅ placeholder confirmed live in the TUI, 68/68 | No `writev`/`sendmsg`, no chunked encoding, no `TCP_CORK` — #111/#113/#116/#122 don't apply to this server |
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

- **Go `net/http` (#42)**: exercised on this Lima VM (arm64 only — no x86_64 host was available for this pass). Two things were checked independently and are reported separately below: the syscall shape (via `strace -f -e trace=network,write,writev,sendto,sendmsg,sendfile` on the server process) and the actual captured/kept byte count and pairing outcome (via the real `tinytap` TUI, driven non-interactively through `tmux send-keys`/`capture-pane` — `stdout -v` only prints headers, not body samples or the truncated flag, so it can't answer this on its own).
  - **Syscall shape (strace)**: `ServeContent`'s `io.ReaderFrom` fast path behaves differently depending on body size. For small.txt (200 B) and image.png (68 B) — both ≤512 B — the whole response goes out as a single `write` (386 B and 237 B on the wire) and `sendfile` is never called. For medium.txt (8192 B) and large.txt (51200 B) — both >512 B — the same fast path always writes the headers plus exactly the *first 512 B* of the body in one `write` call (699 B and 700 B on the wire), then hands the entire remainder to a single `sendfile` call (7680 B and 50688 B, i.e. `total − 512` in both cases). This 512 B split was consistent across both sizes and happened regardless of whether `Content-Type` was already resolved by the file extension.
  - **Captured bytes / pairing (real TUI, not inferred)**: tinytap captures each HTTP exchange from *two* independent vantage points — the server process's outgoing syscalls and the curl client's incoming syscalls — and pairs each side separately, so there are two detail-panel rows per request. Opening both rows in the actual TUI (repeated twice, same result each time) gave:
    - small.txt: **200/200 B**, not truncated, on both the server row and the client row.
    - medium.txt (8192 B total): server row **4096/8192 B — truncated**; client row **4608/8192 B — truncated** (a second run also produced 4608 for the client row).
    - large.txt (51200 B total): server row **4096/51200 B — truncated**; client row **3908/51200 B — truncated** (reproduced identically on a second run).
    - image.png (68 B total, `Content-Type: image/png`): **`Response body: [image/png, 68 bytes]`** on both rows — the #117 binary placeholder rendering was confirmed live in the TUI, not just inferred from the header being correct.
    - No `ABANDONED` exchanges anywhere.
  - **An open question, not resolved here**: the server row's kept-byte count landed at exactly 4096 B for both medium and large — matching the sendfile kprobe's (#68) own per-event cap exactly, not `512 (write prefix) + 4096 (kprobe sample) = 4608` as the syscall-shape numbers above would suggest. That 4608 figure *is* what the client row shows instead. Whether the write's 512 B prefix is being dropped rather than accumulated into the server-side body sample wasn't investigated further — noting it here rather than asserting a cause. The client row's own kept-byte count (4608 for medium, 3908 for large) isn't a fixed cap either; it comes from however many `read`/`recvfrom` calls curl happened to make, each individually capped at 4096 B, so it's expected to vary run to run rather than land on a round number.
  - **x86_64**: not tested — no x86_64 host was available in this session. `internal/loader/load.go` unconditionally skips attaching the sendfile kprobe when `runtime.GOARCH != "arm64"` (#112 tracks adding it), so the *sendfile* portion of medium/large should be entirely uncaptured there, but this is a reading of the code, not something run and observed.
  - **Net effect**: none of `writev`, `sendmsg`, or chunked `Transfer-Encoding` appear anywhere in this server's default paths, so #111, #113, #116, and #122 are all non-issues for Go's `net/http` — the only capture gap here is the sendfile path itself (#36's cap plus #112's still-unverified x86_64 kprobe). No `TCP_CORK`/`MSG_MORE` — only the usual `TCP_NODELAY` + keepalive `setsockopt`s.
  - **Net effect**: none of `writev`, `sendmsg`, or chunked `Transfer-Encoding` appear anywhere in this server's default paths, so #111, #113, #116, and #122 are all non-issues for Go's `net/http` — the only capture gap here is the sendfile path itself (#36's cap plus #112's missing x86_64 kprobe). No `TCP_CORK`/`MSG_MORE` — only the usual `TCP_NODELAY` + keepalive `setsockopt`s.

## Reusable test fixtures

> Script and body-size files go here so #29 can wrap them with assertions.
