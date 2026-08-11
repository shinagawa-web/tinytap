#!/usr/bin/env bash
# TLS e2e test against a real Node.js HTTPS server — the scenario #268/#269
# investigated: Node.js statically bundles OpenSSL (no libssl.so mapping),
# but unstripped builds (NodeSource, nodejs.org official/nvm) still export
# SSL_read/SSL_write/SSL_set_fd/SSL_free from the executable itself, so
# internal/tls.Find's exe-fallback (#269) should discover and attach to
# `node`'s own binary instead of a mapped library.
#
# Split out from scripts/test-e2e.sh (whose TLS scenario covers the
# libssl-mapped path via a Python HTTPS server) the same way
# test-e2e-tls-nginx.sh was split out for the docker-compose scenario — a
# distinct capture path deserves its own harness rather than growing the
# main script's scenario count further.
#
# Requires: node (built with a statically-bundled, unstripped OpenSSL — true
# for the NodeSource and official nodejs.org/nvm distributions verified in
# #268; distro-packaged node from apt/apk dynamically links libssl.so
# instead and doesn't exercise this fallback at all), openssl. tinytap runs
# unprivileged via setcap, including cap_sys_admin since this is a TLS
# uprobe attach (see the docs site's Running Without Full Root page); sudo
# is only used for that one-off setcap call.
# Usage: bash scripts/test-e2e-tls-node.sh

set -euo pipefail

TLS_PORT="${TLS_PORT:-18085}"
# setcap'd file capabilities are silently dropped at exec on a nosuid mount
# (e.g. /tmp is nosuid on this dev VM) — TT_BIN must live somewhere else, so
# it's built into the repo root instead (gitignored, like the plain `tinytap`
# build artifact). Kept to 15 chars: pkill -x below matches against
# /proc/<pid>/comm, which the kernel truncates to 15 — a longer binary name
# would silently never match, hanging the script's own cleanup.
TT_BIN="${PWD}/tinytap-nod-e2e"
TT_CFG=/tmp/tinytap-node-e2e-config.toml
TT_OUT=/tmp/tinytap-node-e2e.log
CERT_DIR=/tmp/tinytap-node-e2e-certs
NODE_SCRIPT=/tmp/tinytap-node-e2e-server.js
NODE_LOG=/tmp/tinytap-node-e2e-server.log
NODE_PID=""
FAILURES=0

command -v node >/dev/null 2>&1 || { echo "FAIL: node not found — see #268/#269"; exit 1; }

cleanup() {
    pkill -INT -x tinytap-nod-e2e 2>/dev/null || true
    if [[ -n "${NODE_PID}" ]]; then
        kill "${NODE_PID}" 2>/dev/null || true
    fi
    rm -f "${TT_BIN}"
    wait 2>/dev/null || true
}
# check_no_leftover_processes (#154) also runs on every EXIT path — see
# scripts/test-e2e.sh for the full rationale.
trap 'cleanup; check_no_leftover_processes' EXIT

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
        grep -q "tinytap running" "${TT_OUT}" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# wait_for_tls_attach waits for sslWatcher's background discovery+attach for
# pid — see scripts/test-e2e.sh's copy of this function for the full
# rationale (30s budget: two uprobe attaches plus a /proc+ELF scan).
wait_for_tls_attach() {
    local pid=$1
    for _ in $(seq 1 300); do
        grep -q "SSL_write/SSL_read/SSL_free uprobes attached for pid ${pid}" "${TT_OUT}" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "  (tinytap output so far:)"
    cat "${TT_OUT}" 2>/dev/null || true
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

check_no_leftover_processes() {
    local leftover=0
    if pgrep -x tinytap-nod-e2e >/dev/null 2>&1; then
        echo "FAIL: tinytap-nod-e2e still running after cleanup"
        pgrep -a -x tinytap-nod-e2e || true
        leftover=1
    fi
    if [[ -n "${NODE_PID}" ]] && kill -0 "${NODE_PID}" 2>/dev/null; then
        echo "FAIL: NODE_PID=${NODE_PID} still running after cleanup"
        leftover=1
    fi
    if [[ "${leftover}" -ne 0 ]]; then
        echo "FAIL: leftover process(es) after cleanup — see above"
        exit 1
    fi
}

echo "==> node --version: $(node --version) ($(command -v node))"

echo "==> building tinytap"
go build -o "${TT_BIN}" ./cmd/tinytap/

echo "==> setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog on tinytap-nod-e2e"
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog=eip "${TT_BIN}"

echo "==> generating self-signed cert"
mkdir -p "${CERT_DIR}"
openssl req -x509 -newkey rsa:2048 -keyout "${CERT_DIR}/key.pem" -out "${CERT_DIR}/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

echo "==> Node.js HTTPS server on ${TLS_PORT}"
cat >"${NODE_SCRIPT}" <<EOF
const https = require('https');
const fs = require('fs');
const options = {
  key: fs.readFileSync('${CERT_DIR}/key.pem'),
  cert: fs.readFileSync('${CERT_DIR}/cert.pem'),
};
https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('ok');
}).listen(${TLS_PORT}, '127.0.0.1');
EOF
node "${NODE_SCRIPT}" >"${NODE_LOG}" 2>&1 &
NODE_PID=$!
wait_for_port localhost "${TLS_PORT}" || { echo "FAIL: node server did not listen on ${TLS_PORT}"; exit 1; }

echo "==> ${TT_BIN} --config ${TT_CFG}"
printf 'output = "stdout"\n' >"${TT_CFG}"
: >"${TT_OUT}"
"${TT_BIN}" --config "${TT_CFG}" >"${TT_OUT}" 2>&1 &
wait_for_tinytap || { echo "FAIL: tinytap did not become ready"; exit 1; }

echo "==> firing TLS warm-up request (triggers SSL uprobe discovery+attach)"
curl -fsSk --retry 3 --retry-delay 0 "https://localhost:${TLS_PORT}/" >/dev/null

wait_for_tls_attach "${NODE_PID}" || { echo "FAIL: TLS uprobes did not attach for node pid ${NODE_PID}"; exit 1; }

echo "==> firing TLS request"
curl -fsSk --retry 3 --retry-delay 0 "https://localhost:${TLS_PORT}/" >/dev/null

echo
echo "=== assertions ==="
assert_contains "uprobes attached via node's own executable (exe-fallback, not a mapped libssl.so)" \
    "SSL_write/SSL_read/SSL_free uprobes attached for pid ${NODE_PID} \(.*/node\)\$"
assert_contains "TLS: GET / paired with 200 (decrypted via SSL uprobe, Node.js target)" \
    "\[${NODE_PID}\].*GET[[:space:]]+/[[:space:]].*200"

echo
if [[ "${FAILURES}" -eq 0 ]]; then
    echo "PASS (all assertions)"
else
    echo "FAIL (${FAILURES} assertion(s) failed)"
    echo "--- full tinytap output ---"
    cat "${TT_OUT}"
fi
trap - EXIT
cleanup
check_no_leftover_processes
exit "${FAILURES}"
