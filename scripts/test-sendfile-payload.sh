#!/usr/bin/env bash
# Manual smoke-test for PR #107 (sendfile body capture via fentry).
#
# Verifies that fentry/tcp_sendmsg_locked loads and attaches successfully
# so that sendfile events carry payload bytes.  Two kinds of checks:
#
#   1. Functional: tinytap captures the HTTP exchange for a ServeFile request.
#   2. Structural:  fentry program appears in bpftool prog list; no
#      "sendfile payload capture disabled" warning in tinytap stderr.
#
# Usage: bash scripts/test-sendfile-payload.sh
# Requires: root (for tinytap + bpftool), go, curl

set -euo pipefail

WORKTREE="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-19180}"
TT_OUT=/tmp/tinytap-sf.log
TT_ERR=/tmp/tinytap-sf.err
SRV_LOG=/tmp/tinytap-sf-srv.log
FAILURES=0

cleanup() {
    sudo pkill -INT -x tinytap-sf 2>/dev/null || true
    kill "${SRV_PID:-}" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

assert_contains() {
    local desc="$1" file="$2" pattern="$3"
    if grep -qE "${pattern}" "${file}" 2>/dev/null; then
        echo "  PASS: ${desc}"
    else
        echo "  FAIL: ${desc}"
        echo "        pattern : ${pattern}"
        echo "        in file : ${file}"
        FAILURES=$((FAILURES + 1))
    fi
}

assert_absent() {
    local desc="$1" file="$2" pattern="$3"
    if grep -qE "${pattern}" "${file}" 2>/dev/null; then
        echo "  FAIL: ${desc} (unexpected match)"
        echo "        pattern : ${pattern}"
        grep -E "${pattern}" "${file}" | head -3 | sed 's/^/        /'
        FAILURES=$((FAILURES + 1))
    else
        echo "  PASS: ${desc}"
    fi
}

# ── Build ─────────────────────────────────────────────────────────────────────
echo "==> building tinytap from ${WORKTREE}"
go build -C "${WORKTREE}" -o /tmp/tinytap-sf ./cmd/tinytap/

# ── Go HTTP server (http.ServeFile → sendfile path) ───────────────────────────
echo "==> writing Go file server"
cat > /tmp/tinytap-sf-srv.go <<'GOEOF'
package main

import (
    "net/http"
    "os"
    "strings"
)

func main() {
    port := os.Args[1]

    // Write a temp file with recognisable content.
    f, err := os.CreateTemp("", "tinytap-sf-*.bin")
    if err != nil { panic(err) }
    f.WriteString(strings.Repeat("F", 4096))
    f.Close()

    http.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, f.Name())
    })
    http.ListenAndServe(":"+port, nil)
}
GOEOF

echo "==> starting Go server on :${PORT}"
go run /tmp/tinytap-sf-srv.go "${PORT}" >"${SRV_LOG}" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/"${PORT}") 2>/dev/null; then
        exec 3<&- 2>/dev/null || true; break
    fi
    sleep 0.1
done

# ── Start tinytap ─────────────────────────────────────────────────────────────
echo "==> sudo /tmp/tinytap-sf --output stdout"
: >"${TT_OUT}" >"${TT_ERR}"
sudo /tmp/tinytap-sf --output stdout >"${TT_OUT}" 2>"${TT_ERR}" &

for _ in $(seq 1 50); do
    grep -q "tinytap running" "${TT_OUT}" 2>/dev/null && break
    sleep 0.1
done

# ── Fire request ──────────────────────────────────────────────────────────────
echo "==> GET /file (http.ServeFile → sendfile path)"
curl -fsS "http://127.0.0.1:${PORT}/file" >/dev/null

sleep 1
cleanup
trap - EXIT

# ── Assertions ────────────────────────────────────────────────────────────────
echo
echo "=== assertions ==="

# 1. HTTP exchange captured
assert_contains "GET /file captured with 200" \
    "${TT_OUT}" "GET[[:space:]]*/file[[:space:]].*200"

# 2. kprobe loaded (no warning in stderr)
assert_absent "no 'sendfile payload capture disabled' warning" \
    "${TT_ERR}" "sendfile payload capture disabled"

# 3. fentry program appears in bpftool (best-effort; skip if bpftool absent)
if command -v bpftool &>/dev/null; then
    BPFTOOL_OUT=$(sudo bpftool prog list 2>/dev/null || true)
    if echo "${BPFTOOL_OUT}" | grep -q "handle_tcp_sendmsg_locked"; then
        echo "  PASS: fentry/tcp_sendmsg_locked visible in bpftool prog list"
    else
        echo "  FAIL: fentry/tcp_sendmsg_locked not found in bpftool prog list"
        FAILURES=$((FAILURES + 1))
    fi
else
    echo "  SKIP: bpftool not found"
fi

echo
if [[ "${FAILURES}" -eq 0 ]]; then
    echo "PASS"
    exit 0
else
    echo "FAIL (${FAILURES} assertion(s))"
    echo
    echo "=== tinytap stdout ==="
    cat "${TT_OUT}"
    echo
    echo "=== tinytap stderr ==="
    cat "${TT_ERR}"
    exit 1
fi
