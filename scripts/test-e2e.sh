#!/usr/bin/env bash
# End-to-end test: starts tinytap and python http.server, fires known HTTP
# requests, and asserts the captured output matches expected patterns.
# Requires root (sudo) to attach eBPF probes.
#
# Usage: bash scripts/test-e2e.sh
# Exit code 0 = all assertions passed; non-zero = failure.

set -euo pipefail

PORT="${PORT:-18080}"
URL="http://localhost:${PORT}/"
TT_OUT=/tmp/tinytap-e2e.log
PY_LOG=/tmp/tinytap-e2e-py.log

PY_PID=""
TT_PID=""
FAILURES=0

cleanup() {
    sudo pkill -INT -x tinytap-e2e 2>/dev/null || true
    if [[ -n "${PY_PID}" ]]; then
        kill "${PY_PID}" 2>/dev/null || true
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

echo "==> python3 -m http.server ${PORT}"
python3 -m http.server "${PORT}" >"${PY_LOG}" 2>&1 &
PY_PID=$!
wait_for_port localhost "${PORT}" || { echo "FAIL: http.server did not listen on ${PORT}"; exit 1; }

echo "==> sudo /tmp/tinytap-e2e --output stdout"
: >"${TT_OUT}"
sudo /tmp/tinytap-e2e --output stdout >"${TT_OUT}" 2>&1 &
TT_PID=$!
wait_for_tinytap || { echo "FAIL: tinytap did not become ready"; exit 1; }

echo "==> firing requests"
curl -fsS "${URL}" >/dev/null
curl -fsS -I "${URL}" >/dev/null
curl -fsS -X POST "${URL}" -d "hello" >/dev/null || true  # python returns 501

sleep 1

cleanup
trap - EXIT

echo
echo "=== assertions ==="
assert_contains "GET / paired with 200"   "GET[[:space:]]+/[[:space:]]+200"
assert_contains "HEAD / paired with 200"  "HEAD[[:space:]]+/[[:space:]]+200"
assert_contains "POST / captured"         "POST[[:space:]]+/"

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
