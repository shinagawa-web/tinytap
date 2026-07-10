#!/usr/bin/env bash
# Self-contained TUI showcase, driven by scripts/tinytap.tape (`vhs`).
#
# Starts `python3 -m http.server`, fires a handful of varied requests in the
# background, then runs `sudo ./tinytap --output tui` in the foreground so
# the tape can drive the live table directly (scroll, open the detail
# panel, quit with `q`). Cleans up the server and traffic generator once
# the TUI exits.

set -euo pipefail

PORT="${PORT:-8082}"
BASE="http://localhost:${PORT}"
DEMO_DIR="$(mktemp -d)"
PY_LOG=/tmp/tinytap-tape-py.log

PY_PID=""
TRAFFIC_PID=""

cleanup() {
    [[ -n "${TRAFFIC_PID}" ]] && kill "${TRAFFIC_PID}" 2>/dev/null || true
    [[ -n "${PY_PID}" ]] && kill "${PY_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "${DEMO_DIR}"
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

# Sample files so requests show varied paths/status codes in the table.
echo '{"tinytap":"tui demo"}' > "${DEMO_DIR}/data.json"
echo '<html><body>hi</body></html>' > "${DEMO_DIR}/index.html"

(cd "${DEMO_DIR}" && exec python3 -m http.server "${PORT}") > "${PY_LOG}" 2>&1 &
PY_PID=$!
wait_for_port localhost "${PORT}" || { echo "http.server failed to listen on ${PORT}" >&2; exit 1; }

# Spaced out so rows stream into the table visibly instead of all landing
# in the same frame.
(
    sleep 1.5
    curl -fsS "${BASE}/" -o /dev/null
    sleep 1.2
    curl -fsS "${BASE}/data.json" -o /dev/null
    sleep 1.2
    curl -fsS -I "${BASE}/index.html" -o /dev/null
    sleep 1.2
    curl -fsS "${BASE}/missing" -o /dev/null || true
    sleep 1.2
    curl -fsS "${BASE}/index.html" -o /dev/null
) &
TRAFFIC_PID=$!

sudo ./tinytap --output tui
