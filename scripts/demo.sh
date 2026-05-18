#!/usr/bin/env bash
# Orchestrated smoke test for `make run`.
#
# - Starts `python3 -m http.server` on $PORT (default 8081).
# - Runs `sudo ./tinytap` and pipes its output through grep into a file.
#   Output never reaches the live terminal, so VS Code Remote / Claude
#   Code can't relay our log lines back into the BPF event stream and
#   amplify the feedback loop (see README §1.5 + commit history for #16).
# - Fires one `curl` at the server.
# - Stops everything, then prints the captured events.

set -euo pipefail

PORT="${PORT:-8081}"
URL="http://localhost:${PORT}/"
TT_LOG=/tmp/tinytap-demo.log
PY_LOG=/tmp/tinytap-demo-py.log
GREP_RE='comm=(python3|curl)( |$)'

PY_PID=""

cleanup() {
    # Stop tinytap if still running. pkill with -INT lets it tear down
    # ringbuf/tracepoints cleanly rather than leaving them attached.
    sudo pkill -INT -x tinytap 2>/dev/null || true
    if [[ -n "${PY_PID}" ]]; then
        kill "${PY_PID}" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
}
trap cleanup EXIT

echo "==> python3 -m http.server ${PORT}   (server log: ${PY_LOG})"
python3 -m http.server "${PORT}" > "${PY_LOG}" 2>&1 &
PY_PID=$!
sleep 1

echo "==> sudo ./tinytap | grep '${GREP_RE}'   (event log: ${TT_LOG})"
sudo ./tinytap 2>&1 | grep -E "${GREP_RE}" > "${TT_LOG}" &
sleep 1

echo "==> curl ${URL}"
curl -s "${URL}" > /dev/null

# Let kernel events drain into the ringbuf reader.
sleep 1

# Stop now so the cat below shows only the captured run.
cleanup
trap - EXIT

echo
echo "=== captured events (filtered to comm=python3/curl) ==="
cat "${TT_LOG}"
