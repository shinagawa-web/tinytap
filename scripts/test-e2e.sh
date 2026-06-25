#!/usr/bin/env bash
# End-to-end test: starts tinytap and python http.server, fires known HTTP
# requests, and asserts the captured output matches expected patterns.
# Requires root (sudo) to attach eBPF probes.
#
# Scenarios:
#   1. Normal: GET / HEAD / POST against python http.server → paired lines.
#   2. Abandoned: slow server killed mid-request → ABANDONED line in output.
#
# Usage: bash scripts/test-e2e.sh
# Exit code 0 = all assertions passed; non-zero = failure.

set -euo pipefail

PORT="${PORT:-18080}"
SLOW_PORT="${SLOW_PORT:-18081}"
URL="http://localhost:${PORT}/"
TT_OUT=/tmp/tinytap-e2e.log
PY_LOG=/tmp/tinytap-e2e-py.log
SLOW_LOG=/tmp/tinytap-e2e-slow.log

PY_PID=""
SLOW_PY_PID=""
SLOW_CURL_PID=""
FAILURES=0

cleanup() {
    sudo pkill -INT -x tinytap-e2e 2>/dev/null || true
    if [[ -n "${PY_PID}" ]]; then
        kill "${PY_PID}" 2>/dev/null || true
    fi
    if [[ -n "${SLOW_PY_PID}" ]]; then
        kill -9 "${SLOW_PY_PID}" 2>/dev/null || true
    fi
    if [[ -n "${SLOW_CURL_PID}" ]]; then
        kill "${SLOW_CURL_PID}" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    local host=$1 port=$2
    for _ in $(seq 1 50); do
        if (exec 3<>/dev/tcp/"${host}"/"${port}") 2>/dev/null; then
            exec 3<&- 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_for_tinytap() {
    for _ in $(seq 1 50); do
        if grep -q "tinytap running" "${TT_OUT}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

assert_contains() {
    local description="$1"
    local pattern="$2"
    if grep -qE "${pattern}" "${TT_OUT}"; then
        echo "  PASS: ${description}"
    else
        echo "  FAIL: ${description} (pattern: ${pattern})"
        FAILURES=$((FAILURES + 1))
    fi
}

echo "==> building tinytap"
go build -o /tmp/tinytap-e2e ./cmd/tinytap/

# ── Scenario 2 setup: slow server (never responds) ───────────────────────────
# A Python server that accepts a connection but never sends a response,
# simulating a hung backend. We kill it with SIGKILL so the OS-level close
# triggers the SyscallClose path in tinytap.
echo "==> slow server on ${SLOW_PORT}"
python3 - "${SLOW_PORT}" >"${SLOW_LOG}" 2>&1 <<'PYEOF' &
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', port))
s.listen(1)
conn, _ = s.accept()
# Absorb the request bytes so curl sends its full payload, then hang forever.
conn.recv(4096)
time.sleep(9999)
PYEOF
SLOW_PY_PID=$!
wait_for_port localhost "${SLOW_PORT}" || { echo "FAIL: slow server did not listen on ${SLOW_PORT}"; exit 1; }

# ── Scenario 1 setup: normal http.server ─────────────────────────────────────
echo "==> python3 -m http.server ${PORT}"
python3 -m http.server "${PORT}" >"${PY_LOG}" 2>&1 &
PY_PID=$!
wait_for_port localhost "${PORT}" || { echo "FAIL: http.server did not listen on ${PORT}"; exit 1; }
kill -0 "${PY_PID}" 2>/dev/null || { echo "FAIL: http.server exited immediately (port ${PORT} already in use?)"; exit 1; }

# ── Start tinytap ─────────────────────────────────────────────────────────────
echo "==> sudo /tmp/tinytap-e2e --output stdout"
: >"${TT_OUT}"
sudo /tmp/tinytap-e2e --output stdout >"${TT_OUT}" 2>&1 &
wait_for_tinytap || { echo "FAIL: tinytap did not become ready"; exit 1; }

# ── Scenario 1: normal requests ───────────────────────────────────────────────
echo "==> firing normal requests"
curl -fsS --retry 3 --retry-delay 0 "${URL}" >/dev/null
curl -fsS --retry 3 --retry-delay 0 -I "${URL}" >/dev/null
post_exit=0
curl -fsS -X POST "${URL}" -d "hello" >/dev/null || post_exit=$?
[[ ${post_exit} -eq 0 || ${post_exit} -eq 22 ]] || exit "${post_exit}"

# ── Scenario 2: abandoned request via kill -9 ────────────────────────────────
echo "==> firing request to slow server"
curl -fsS "http://localhost:${SLOW_PORT}/" >/dev/null &
SLOW_CURL_PID=$!
sleep 0.3  # give curl time to send its request headers

echo "==> kill -9 slow server (triggers OS-level close)"
kill -9 "${SLOW_PY_PID}" 2>/dev/null || true
SLOW_PY_PID=""
wait "${SLOW_CURL_PID}" 2>/dev/null || true
SLOW_CURL_PID=""

sleep 1

cleanup
trap - EXIT

echo
echo "=== assertions ==="
assert_contains "GET / paired with 200"   "\[${PY_PID}\].*GET[[:space:]]+/[[:space:]].*200"
assert_contains "HEAD / paired with 200"  "\[${PY_PID}\].*HEAD[[:space:]]+/[[:space:]].*200"
assert_contains "POST / captured"         "\[${PY_PID}\].*POST[[:space:]]+/"
assert_contains "abandoned: peer closed"  "ABANDONED|peer closed"

echo
if [[ "${FAILURES}" -eq 0 ]]; then
    echo "PASS (all assertions)"
    exit 0
else
    echo "FAIL (${FAILURES} assertion(s) failed)"
    echo
    echo "=== captured output ==="
    cat "${TT_OUT}"
    exit 1
fi
