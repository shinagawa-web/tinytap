# TLS Compatibility

> Part of v0.5.0 (#144). Documents which TLS-terminating servers/clients tinytap can capture via the `SSL_write`/`SSL_read`/`SSL_free` libssl uprobes (#146/#147/#173), and how that was verified.

## Why this is a separate doc from server-compat.md

[`server-compat.md`](server-compat.md)'s table measures how many **wire bytes** of a plaintext body survive tinytap's per-syscall sample cap (`sendfile`/`writev` budgets, #36/#111/#128). That question doesn't apply to TLS capture: the uprobe reads the **full plaintext buffer** directly from the `SSL_write`/`SSL_read` call's arguments (up to a separate 4096 B cap, `MAX_SSL_PAYLOAD` in `bpf/tinytap_uprobe.bpf.c`), before encryption or after decryption — however many ciphertext syscalls happen underneath is invisible to this capture path entirely (see #148's investigation). Reusing the same table would conflate two unrelated capture mechanisms under the same columns.

## What's covered

| Server/client | Verified via | fd-resolvable? | Result |
|---|---|---|---|
| Python `ssl`-wrapped `http.server` | `scripts/test-e2e.sh` (no Docker) | ✅ calls `SSL_set_fd` (#167) | ✅ paired, decrypted correctly |
| nginx, Debian-based (`nginx:latest`) | `scripts/test-e2e-tls-nginx.sh` (docker-compose, #178) | ✅ calls `SSL_set_fd` directly (`ngx_ssl_create_connection()`) | ✅ paired, decrypted correctly |
| nginx, Alpine-based (`nginx:alpine`) | `scripts/test-e2e-tls-nginx.sh` (docker-compose, #178) | ✅ same as above | ✅ paired, decrypted correctly |
| curl | investigated in #167 | ❌ never calls `SSL_set_fd` (custom `BIO_METHOD` + `SSL_set_bio`) | ⚠️ plaintext captured by the uprobe but dropped before the HTTP parser today — needs the SSL*-keyed parser stream tracked in #179 |

## nginx docker-compose validation (#178)

The primary motivating scenario from #144: nginx as a TLS-terminating reverse proxy in front of a plaintext backend, in a docker-compose setup — confirming the assumption that mainstream nginx Docker images dynamically link `libssl.so` with symbols intact, for both major base image families.

**Setup** (`scripts/docker/nginx-tls/`): a `python:3-alpine` backend (`python3 -m http.server 80`) behind an nginx container terminating TLS on `:443` (self-signed cert, generated fresh per run) and `proxy_pass`-ing to the backend. `scripts/test-e2e-tls-nginx.sh` runs this against both `nginx:latest` (Debian-based) and `nginx:alpine` (Alpine-based), asserting the actual image running matches what was requested (not just what the compose file defaults to) before firing a request and checking tinytap's output for a paired `GET / → 200` line attributed to the nginx worker process.

**Key fact this confirms**: eBPF operates at the host kernel level. A container's process is an ordinary host process under a different PID namespace — tinytap (running on the host, outside any container) sees it exactly like any other process, with no container-aware code needed. `internal/tls.Find`'s existing `/proc/<pid>/root/<path>` resolution (already needed for chroot-like cases) handles resolving the container's own libssl path from the host's view for free.

**Gotchas hit while wiring this up** (both are test-harness issues, not tinytap bugs):
- Debian/Ubuntu ships `libssl.so.3` without the execute bit (`chmod 0644`); `cilium/ebpf`'s `link.OpenExecutable` requires it. `AttachSSLSetFd`/`AttachSSLReadWrite` deliberately never `chmod` their target themselves (see `ErrLibSSLNotExecutable`'s doc comment) — the e2e harness sets it explicitly instead, same as `scripts/test-e2e.sh`'s TLS scenario.
- `pkill -x` matches against `/proc/<pid>/comm`, which the kernel truncates to 15 characters — a binary named `tinytap-e2e-nginx` (17 chars) never matches, so the harness's own cleanup silently failed to signal tinytap, hanging the script indefinitely. Binary names used by any script that `pkill -x`s them need to stay ≤15 characters.

## Running it

```bash
# No Docker needed — validates the same wiring against a Python HTTPS server
bash scripts/test-e2e.sh

# Needs Docker + the docker compose v2 plugin — validates against real nginx images
bash scripts/test-e2e-tls-nginx.sh
```
