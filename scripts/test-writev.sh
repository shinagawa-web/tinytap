#!/usr/bin/env bash
# Manual smoke-test for PR #106 (writev/readv/sendfile capture).
#
# Starts a Go net/http file server on a random port, fires three requests
# with different body sizes, and checks that tinytap captures the responses
# via writev (which Go's net/http uses for small dynamic responses) and
# sendfile (which it uses for http.ServeFile / large static files).
#
# Usage: bash scripts/test-writev.sh
# Requires: root (for tinytap), go, curl

set -euo pipefail

PORT="${PORT:-19080}"
TT_OUT=/tmp/tinytap-writev.log
SRV_LOG=/tmp/tinytap-writev-srv.log
FAILURES=0

cleanup() {
    sudo pkill -INT -x tinytap-writev 2>/dev/null || true
    kill "${SRV_PID:-}" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

assert_contains() {
    local desc="$1" pattern="$2"
    if grep -qE "${pattern}" "${TT_OUT}" 2>/dev/null; then
        echo "  PASS: ${desc}"
    else
        echo "  FAIL: ${desc} (pattern: ${pattern})"
        FAILURES=$((FAILURES + 1))
    fi
}

# ── Build ─────────────────────────────────────────────────────────────────────
WORKTREE=~/tinytap/.claude/worktrees/feat-issue-69

echo "==> building tinytap from ${WORKTREE}"
go build -o /tmp/tinytap-writev "${WORKTREE}/cmd/tinytap/"

# ── Inline Go HTTP server (dynamic + static responses) ────────────────────────
echo "==> writing Go server"
cat > /tmp/tinytap-writev-srv.go <<'GOEOF'
package main

import (
    "fmt"
    "net/http"
    "os"
    "strings"
)

func main() {
    port := os.Args[1]

    // /hello — small dynamic response (writev path)
    http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "hello from tinytap writev test")
    })

    // /medium — ~1 KiB dynamic response
    http.HandleFunc("/medium", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprint(w, strings.Repeat("x", 1024))
    })

    // /file — serves a temp file via http.ServeFile (sendfile path)
    tmp, err := os.CreateTemp("", "tinytap-*.bin")
    if err != nil {
        panic(err)
    }
    tmp.Write([]byte(strings.Repeat("f", 4096)))
    tmp.Close()
    http.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, tmp.Name())
    })

    http.ListenAndServe(":"+port, nil)
}
GOEOF

echo "==> starting Go server on ${PORT}"
go run /tmp/tinytap-writev-srv.go "${PORT}" >"${SRV_LOG}" 2>&1 &
SRV_PID=$!

# Wait for the server to be ready.
for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/"${PORT}") 2>/dev/null; then
        exec 3<&- 2>/dev/null || true; break
    fi
    sleep 0.1
done

# ── Start tinytap ─────────────────────────────────────────────────────────────
echo "==> sudo /tmp/tinytap-writev --output stdout"
: >"${TT_OUT}"
sudo /tmp/tinytap-writev --output stdout >"${TT_OUT}" 2>&1 &

for _ in $(seq 1 50); do
    grep -q "tinytap running" "${TT_OUT}" 2>/dev/null && break
    sleep 0.1
done

# ── Fire requests ─────────────────────────────────────────────────────────────
echo "==> GET /hello  (small dynamic — writev)"
curl -fsS "http://127.0.0.1:${PORT}/hello" >/dev/null

echo "==> GET /medium (1 KiB dynamic — writev)"
curl -fsS "http://127.0.0.1:${PORT}/medium" >/dev/null

echo "==> GET /file   (4 KiB static  — sendfile)"
curl -fsS "http://127.0.0.1:${PORT}/file" >/dev/null

sleep 1
cleanup
trap - EXIT

# ── Assertions ────────────────────────────────────────────────────────────────
echo
echo "=== assertions ==="
assert_contains "GET /hello captured"  "GET[[:space:]]*/hello[[:space:]].*200"
assert_contains "GET /medium captured" "GET[[:space:]]*/medium[[:space:]].*200"
assert_contains "GET /file captured"   "GET[[:space:]]*/file[[:space:]].*200"

echo
echo "=== raw output (last 30 lines) ==="
tail -30 "${TT_OUT}"

echo
if [[ "${FAILURES}" -eq 0 ]]; then
    echo "PASS"
    exit 0
else
    echo "FAIL (${FAILURES} assertion(s))"
    exit 1
fi
