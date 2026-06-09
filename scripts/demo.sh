#!/usr/bin/env bash
# Orchestrated smoke test for `make run`.
#
# - Starts `python3 -m http.server` on $PORT (default 8081).
# - Runs `sudo ./tinytap` with output redirected to a file. Output never
#   reaches the live terminal, so VS Code Remote / Claude Code can't relay
#   our log lines back into the BPF event stream and amplify the feedback
#   loop (see README §1.5 + commit history for #16).
# - Fires one `curl` at the server.
# - Stops only the processes this script started, then prints the captured
#   events (filtered to comm=python3/curl).

set -euo pipefail

PORT="${PORT:-8081}"
URL="http://localhost:${PORT}/"
TT_LOG=/tmp/tinytap-demo.log
TT_RAW=/tmp/tinytap-demo-raw.log
PY_LOG=/tmp/tinytap-demo-py.log
GREP_RE='comm=(python3|curl)( |$)|\((python3|curl)\)'

PY_PID=""
TT_PID=""

cleanup() {
    # Stop only the tinytap we started (not any other tinytap on the box).
    # sudo forwards SIGINT to the child so ringbuf/tracepoints tear down cleanly.
    if [[ -n "${TT_PID}" ]]; then
        sudo kill -INT "${TT_PID}" 2>/dev/null || true
    fi
    if [[ -n "${PY_PID}" ]]; then
        kill "${PY_PID}" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    # Poll the TCP port via bash's /dev/tcp until it accepts connections,
    # so we don't depend on a fixed sleep that goes flaky on slow machines.
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
    # tinytap logs "tinytap running" after ringbuf is open and tracepoints
    # are attached. Wait for that line instead of sleeping a fixed interval.
    for _ in $(seq 1 50); do
        if grep -q "tinytap running" "${TT_RAW}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

echo "==> python3 -m http.server ${PORT}   (server log: ${PY_LOG})"
python3 -m http.server "${PORT}" > "${PY_LOG}" 2>&1 &
PY_PID=$!
wait_for_port localhost "${PORT}" || { echo "http.server failed to listen on ${PORT}" >&2; exit 1; }

echo "==> sudo ./tinytap   (raw log: ${TT_RAW})"
: > "${TT_RAW}"
sudo ./tinytap > "${TT_RAW}" 2>&1 &
TT_PID=$!
wait_for_tinytap || { echo "tinytap did not become ready" >&2; exit 1; }

echo "==> curl ${URL}"
curl -fsS --retry 5 --retry-connrefused "${URL}" > /dev/null

# HEAD exercises the no-body response path: python's http.server still
# advertises Content-Length on a HEAD reply, but sends zero body bytes —
# parser must short-circuit framing via the request-method lookup.
echo "==> curl -I ${URL}"
curl -fsS -I --retry 5 --retry-connrefused "${URL}" > /dev/null

# Let kernel events drain into the ringbuf reader.
sleep 1

# Stop now so the filtered log below covers only this run.
cleanup
trap - EXIT

grep -E "${GREP_RE}" "${TT_RAW}" > "${TT_LOG}" || true

echo
echo "=== captured events (filtered to comm=python3/curl) ==="
cat "${TT_LOG}"
