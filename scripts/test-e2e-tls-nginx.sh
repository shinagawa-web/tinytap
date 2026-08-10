#!/usr/bin/env bash
# TLS e2e test against real nginx Docker images terminating TLS in front of
# a plaintext backend — the docker-compose scenario from #144's motivating
# case (docker-compose service-to-service connectivity debugging), split
# out into #178 since it needs Docker (scripts/test-e2e.sh's TLS scenario
# validates the same wiring without Docker, against a Python HTTPS server).
#
# Runs the scenario against both a Debian-based nginx image (nginx:latest)
# and an Alpine-based one (nginx:alpine) — the two variants #144's open
# questions asked about — confirming both dynamically link libssl.so with
# symbols intact.
#
# nginx runs as a container, but eBPF operates at the host kernel level:
# container processes are ordinary host processes under a different PID
# namespace, so tinytap (running on the host) sees them like any other
# process — no container-aware code needed on tinytap's side.
#
# Requires: docker, docker compose (v2 plugin), openssl. tinytap itself runs
# unprivileged via setcap, including cap_sys_admin since every scenario here
# is a TLS uprobe attach (see the docs site's Running Without Full Root
# page); sudo is still needed for docker compose and the libssl chmod below.
# Usage: bash scripts/test-e2e-tls-nginx.sh

set -euo pipefail

DIR="$(cd "$(dirname "$0")/docker/nginx-tls" && pwd)"
PORT="${PORT:-18443}"
# setcap'd file capabilities are silently dropped at exec on a nosuid mount
# (e.g. /tmp is nosuid on this dev VM) — TT_BIN must live somewhere else, so
# it's built into the repo root instead (gitignored, like the plain `tinytap`
# build artifact).
TT_BIN="${PWD}/tinytap-ngx-e2e"
TT_CFG=/tmp/tinytap-ngx-e2e-config.toml
TT_OUT=/tmp/tinytap-ngx-e2e.log
FAILURES=0

command -v docker >/dev/null 2>&1 || { echo "FAIL: docker not found — see #178"; exit 1; }
sudo docker compose version >/dev/null 2>&1 || { echo "FAIL: docker compose (v2 plugin) not found — see #178"; exit 1; }

cleanup() {
    pkill -INT -x tinytap-ngx-e2e 2>/dev/null || true
    rm -f "${TT_BIN}"
    (cd "${DIR}" && sudo docker compose down -v --timeout 1 >/dev/null 2>&1) || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    local host=$1 port=$2
    for _ in $(seq 1 100); do
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

# wait_for_new_tls_attach waits for a "uprobes attached" line to appear
# after line_count (a marker taken right before the warm-up request) —
# unlike scripts/test-e2e.sh's wait_for_tls_attach, the pid isn't known in
# advance here: TLS handshakes happen in nginx worker processes forked from
# the container's PID-1 master, which docker inspect can't report.
wait_for_new_tls_attach() {
    local line_count=$1
    for _ in $(seq 1 300); do
        if tail -n "+$((line_count + 1))" "${TT_OUT}" 2>/dev/null | grep -q "uprobes attached"; then
            return 0
        fi
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

echo "==> building tinytap"
go build -o "${TT_BIN}" ./cmd/tinytap/

echo "==> setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin on tinytap-ngx-e2e (see the docs site's Running Without Full Root page)"
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin=eip "${TT_BIN}"

echo "==> generating self-signed cert"
mkdir -p "${DIR}/certs"
openssl req -x509 -newkey rsa:2048 -keyout "${DIR}/certs/key.pem" -out "${DIR}/certs/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

LIBSSL_PATH="$(ldconfig -p | grep 'libssl\.so\.3' | awk '{print $NF}' | head -1)"
if [[ -n "${LIBSSL_PATH}" && ! -x "${LIBSSL_PATH}" ]]; then
    echo "==> chmod +x ${LIBSSL_PATH} (Debian/Ubuntu ships libssl3 without the execute bit)"
    sudo chmod +x "${LIBSSL_PATH}"
fi

run_scenario() {
    local image="$1"
    local label="$2"

    echo
    echo "=== ${label} (${image}) ==="

    echo "==> docker compose up (${image})"
    # docker compose auto-loads a .env file from its project directory —
    # more reliable than passing vars through `sudo -E`, which this
    # environment's sudoers policy doesn't honor (silently ignored, so a
    # prior version of this script always got the ${NGINX_IMAGE:-nginx:latest}
    # fallback regardless of which image this loop thought it was testing).
    # PORT must go in here too: docker-compose.yml's port mapping reads it
    # from the same .env, not from this script's shell variable, so a PORT
    # override wouldn't otherwise reach the actual published port.
    printf 'NGINX_IMAGE=%s\nPORT=%s\n' "${image}" "${PORT}" > "${DIR}/.env"
    (cd "${DIR}" && sudo docker compose up -d)
    local actual_image
    actual_image=$(sudo docker inspect --format '{{.Config.Image}}' "$(cd "${DIR}" && sudo docker compose ps -q nginx)")
    echo "==> image actually used: ${actual_image}"
    if [[ "${actual_image}" != "${image}" ]]; then
        echo "FAIL: expected nginx container to run ${image}, got ${actual_image}"
        exit 1
    fi
    wait_for_port localhost "${PORT}" || { echo "FAIL: nginx (${image}) did not listen on ${PORT}"; exit 1; }

    printf 'output = "stdout"\n' >"${TT_CFG}"
    echo "==> ${TT_BIN} --config ${TT_CFG}"
    : >"${TT_OUT}"
    "${TT_BIN}" --config "${TT_CFG}" >"${TT_OUT}" 2>&1 &
    wait_for_tinytap || { echo "FAIL: tinytap did not become ready"; exit 1; }

    echo "==> firing warm-up request (triggers SSL uprobe discovery+attach for the nginx worker)"
    local marker
    marker=$(wc -l <"${TT_OUT}")
    curl -fsSk --retry 5 --retry-delay 1 "https://localhost:${PORT}/" >/dev/null

    # The warm-up's own SSL_write/SSL_read happens before the uprobe
    # attaches (same race documented in scripts/test-e2e.sh), so it isn't
    # captured — wait for attach to confirm, then fire the request that's
    # actually guaranteed captured and asserted on below.
    wait_for_new_tls_attach "${marker}" || { echo "FAIL: TLS uprobes did not attach for ${label}"; exit 1; }

    echo "==> firing request"
    curl -fsSk --retry 3 --retry-delay 0 "https://localhost:${PORT}/" >/dev/null
    sleep 0.3

    pkill -INT -x tinytap-ngx-e2e 2>/dev/null || true
    wait 2>/dev/null || true

    assert_contains "${label}: GET / paired with 200 (decrypted via SSL uprobe)" \
        "nginx.*GET[[:space:]]+/[[:space:]].*200"

    (cd "${DIR}" && sudo docker compose down -v --timeout 1 >/dev/null 2>&1) || true
}

echo
echo "=== assertions ==="
run_scenario "nginx:latest" "Debian-based nginx"
run_scenario "nginx:alpine" "Alpine-based nginx"

trap - EXIT
cleanup

echo
if [[ "${FAILURES}" -eq 0 ]]; then
    echo "PASS (all assertions)"
    exit 0
else
    echo "FAIL (${FAILURES} assertion(s) failed)"
    exit 1
fi
