#!/usr/bin/env bash
set -euo pipefail

PORT=19081
TT_BIN="${PWD}/tinytap-fdtype"
TT_CAPS="cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog"
TT_CFG=/tmp/tt-fdtype.toml
TT_OUT=/tmp/tt-fdtype.log

cleanup() {
    pkill -x tinytap-fdtype 2>/dev/null || true
    kill "${PY_PID:-0}" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -f "${TT_BIN}"
}
trap cleanup EXIT

go build -o "${TT_BIN}" ./cmd/tinytap/
sudo setcap "${TT_CAPS}=eip" "${TT_BIN}"

python3 -m http.server "${PORT}" >/tmp/tt-fdtype-py.log 2>&1 &
PY_PID=$!
sleep 1

printf 'output = "stdout"\n' >"${TT_CFG}"
: >"${TT_OUT}"
"${TT_BIN}" --config "${TT_CFG}" >"${TT_OUT}" 2>&1 &
TT_PID=$!
sleep 1
echo "tinytap pid=${TT_PID}"

for _ in $(seq 1 5); do
    (while true; do curl -fsS --no-keepalive "http://localhost:${PORT}/" -o /dev/null 2>/dev/null || true; done) &
done

sleep 2

echo "=== fd count at 2s ==="
sudo ls /proc/"${TT_PID}"/fd 2>/dev/null | wc -l || echo "0 (process dead)"

echo "=== fd link targets (first 30) ==="
sudo ls -la /proc/"${TT_PID}"/fd 2>/dev/null | awk '{print $NF}' | tail -n +2 | sort | uniq -c | sort -rn | head -30 || echo "(process dead)"

echo "=== rss ==="
awk '/VmRSS/{print $2}' /proc/"${TT_PID}"/status 2>/dev/null || echo "0"

echo ""
echo "=== tinytap log (TLS lines) ==="
grep -E "uprobe|tls:|attach|ERROR|error" "${TT_OUT}" | head -20 || true
