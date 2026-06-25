#!/usr/bin/env bash
# Manual smoke test for Transfer-Encoding: chunked support (#60).
#
# Starts nginx as a reverse proxy (proxy_buffering off) in front of a tiny
# Python chunked backend, fires one curl request automatically, then lets
# tinytap run so you can watch the captured events.
#
# Usage:
#   bash scripts/test-chunked.sh          # TUI output (default)
#   bash scripts/test-chunked.sh --stdout  # plain stdout
#
# Requires: sudo (eBPF probes), nginx, python3, curl, go

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROXY_PORT="${PROXY_PORT:-18082}"
BACKEND_PORT="${BACKEND_PORT:-18083}"

NGINX_CONF=/tmp/tinytap-chunked-nginx.conf
NGINX_PID_FILE=/tmp/tinytap-chunked-nginx.pid
SRV_PY=/tmp/tinytap-chunked-srv.py
TT_BIN=/tmp/tinytap-chunked

OUTPUT_MODE="tui"
if [[ "${1:-}" == "--stdout" ]]; then
    OUTPUT_MODE="stdout"
fi

SRV_PID=""

cleanup() {
    if [[ -n "${SRV_PID}" ]]; then
        kill "${SRV_PID}" 2>/dev/null || true
    fi
    if [[ -f "${NGINX_PID_FILE}" ]]; then
        sudo nginx -c "${NGINX_CONF}" -s stop 2>/dev/null || true
    fi
    rm -f "${SRV_PY}" "${NGINX_CONF}"
    wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    local host=$1 port=$2
    for _ in $(seq 1 50); do
        if (exec 3<>/dev/tcp/"${host}"/"${port}") 2>/dev/null; then
            exec 3>&- 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
    echo "ERROR: port ${port} did not open" >&2
    return 1
}

# ── build ────────────────────────────────────────────────────────────────────
echo "==> building tinytap"
go build -C "${REPO_ROOT}" -o "${TT_BIN}" ./cmd/tinytap/

# ── nginx config ─────────────────────────────────────────────────────────────
cat > "${NGINX_CONF}" << EOF
events {}
http {
    server {
        listen ${PROXY_PORT};
        location / {
            proxy_pass http://127.0.0.1:${BACKEND_PORT};
            proxy_http_version 1.1;
            proxy_buffering off;
        }
    }
}
EOF

# ── Python chunked backend ───────────────────────────────────────────────────
cat > "${SRV_PY}" << 'PYEOF'
import sys, time
from http.server import HTTPServer, BaseHTTPRequestHandler

CHUNKS = [b"Hello", b" chunked", b" world!"]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        for c in CHUNKS:
            self.wfile.write(f"{len(c):x}\r\n".encode() + c + b"\r\n")
            self.wfile.flush()
            time.sleep(0.05)   # small delay to keep chunks separate
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

HTTPServer(("", int(sys.argv[1])), Handler).serve_forever()
PYEOF

echo "==> starting Python chunked backend on port ${BACKEND_PORT}"
python3 "${SRV_PY}" "${BACKEND_PORT}" &
SRV_PID=$!
wait_for_port 127.0.0.1 "${BACKEND_PORT}"

echo "==> starting nginx on port ${PROXY_PORT} (proxy_buffering off)"
sudo nginx -c "${NGINX_CONF}"
wait_for_port 127.0.0.1 "${PROXY_PORT}"

# ── fire curl after tinytap has a moment to attach ───────────────────────────
# The curl runs in background once, 2 s after this script continues, giving
# tinytap time to attach its eBPF probes. You can also run curl manually from
# another terminal: curl http://localhost:${PROXY_PORT}/
(
    sleep 2
    echo ""
    echo "  --> curl http://localhost:${PROXY_PORT}/"
    curl -fsS "http://localhost:${PROXY_PORT}/" && echo " (body: Hello chunked world!)"
    echo ""
) &

# ── run tinytap ──────────────────────────────────────────────────────────────
echo "==> sudo ${TT_BIN} --output ${OUTPUT_MODE}"
echo "    (curl fires automatically in ~2 s; Ctrl-C to stop)"
echo ""
sudo "${TT_BIN}" --output "${OUTPUT_MODE}"
