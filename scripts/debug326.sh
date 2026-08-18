#!/usr/bin/env bash
# debug326.sh: reproduce issue #326 with sub-second fd/rss sampling
# and exit-mechanism instrumentation
set -euo pipefail

PORT="${PORT:-19080}"
DURATION="${DURATION:-30}"
CHURN_WORKERS="${CHURN_WORKERS:-5}"

TT_BIN="${PWD}/tinytap-debug326"
TT_CAPS="cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog"
TT_CFG=/tmp/tinytap-debug326-config.toml
TT_OUT=/tmp/tinytap-debug326.log
PY_LOG=/tmp/tinytap-debug326-py.log

TT_PID=""
PY_PID=""
CHURN_PIDS=()

cleanup() {
    pkill -INT -x tinytap-debug326 2>/dev/null || true
    [[ -n "${PY_PID:-}" ]] && kill "${PY_PID}" 2>/dev/null || true
    for pid in "${CHURN_PIDS[@]+"${CHURN_PIDS[@]}"}"; do
        kill "${pid}" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -f "${TT_BIN}"
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

echo "==> building tinytap"
go build -o "${TT_BIN}" ./cmd/tinytap/

echo "==> setcap"
sudo setcap "${TT_CAPS}=eip" "${TT_BIN}"

echo "==> python3 http.server ${PORT}"
python3 -m http.server "${PORT}" >"${PY_LOG}" 2>&1 &
PY_PID=$!
wait_for_port localhost "${PORT}" || { echo "FAIL: http.server did not start"; exit 1; }

printf 'output = "stdout"\n' >"${TT_CFG}"
: >"${TT_OUT}"

echo "==> launching tinytap (capturing exit code and signal)"
"${TT_BIN}" --config "${TT_CFG}" >"${TT_OUT}" 2>&1 &
TT_PID=$!

# Wait for tinytap to be ready
for _ in $(seq 1 50); do
    grep -q "tinytap running" "${TT_OUT}" 2>/dev/null && break
    sleep 0.1
done
echo "  tinytap pid=${TT_PID}"

echo "==> checking if curl links libssl"
CURL_BIN=$(which curl)
ldd "${CURL_BIN}" 2>/dev/null | grep libssl || echo "  curl does NOT link libssl directly"

echo "==> starting ${CHURN_WORKERS} curl workers (SLEEP_BETWEEN_REQS=0)"
for _ in $(seq 1 "${CHURN_WORKERS}"); do
    (while true; do
        curl -fsS --no-keepalive "http://localhost:${PORT}/" -o /dev/null 2>/dev/null || true
    done) &
    CHURN_PIDS+=($!)
done

echo ""
echo "==> sampling fd/rss every 0.5s for ${DURATION}s"
echo "time_s  rss_kb  fd_count  alive"
START=$(date +%s%3N)
while true; do
    NOW=$(date +%s%3N)
    ELAPSED_MS=$(( NOW - START ))
    ELAPSED_S=$(( ELAPSED_MS / 1000 ))
    [[ "${ELAPSED_S}" -ge "${DURATION}" ]] && break

    if [[ -f "/proc/${TT_PID}/status" ]]; then
        RSS=$(awk '/VmRSS/{print $2}' /proc/"${TT_PID}"/status 2>/dev/null || echo 0)
        FDS=$(sudo ls /proc/"${TT_PID}"/fd 2>/dev/null | wc -l || echo 0)
        ALIVE="Y"
    else
        RSS=0; FDS=0; ALIVE="N"
    fi

    printf "%.1f\t%d\t%d\t%s\n" "$(echo "scale=1; ${ELAPSED_MS}/1000" | bc)" "${RSS}" "${FDS}" "${ALIVE}"

    if [[ "${ALIVE}" == "N" ]]; then
        echo ""
        echo "==> tinytap died at ${ELAPSED_MS}ms"
        break
    fi

    sleep 0.5
done

echo ""
echo "==> checking exit mechanism..."

# Check if process is still running
if kill -0 "${TT_PID}" 2>/dev/null; then
    echo "  tinytap is still alive (survived ${DURATION}s)"
    kill -INT "${TT_PID}" 2>/dev/null || true
else
    # Get wait status
    set +e
    wait "${TT_PID}" 2>/dev/null
    EXIT_CODE=$?
    set -e
    echo "  exit code (wait): ${EXIT_CODE}"
    if [[ "${EXIT_CODE}" -gt 128 ]]; then
        SIG=$((EXIT_CODE - 128))
        echo "  killed by signal: ${SIG}"
        case "${SIG}" in
            9)  echo "  → SIGKILL (likely OOM killer)" ;;
            11) echo "  → SIGSEGV (crash/bug)" ;;
            6)  echo "  → SIGABRT (panic/abort)" ;;
            *)  echo "  → signal ${SIG}" ;;
        esac
    elif [[ "${EXIT_CODE}" -eq 0 ]]; then
        echo "  → clean exit (capture loop returned on rd.Read() error)"
    else
        echo "  → non-zero clean exit (error): ${EXIT_CODE}"
    fi
fi

echo ""
echo "==> dmesg OOM check (last 10 lines matching 'tinytap' or 'oom')"
dmesg 2>/dev/null | grep -i -E "tinytap|oom.kill|out.of.memory" | tail -10 || echo "  (none found or no permission)"

echo ""
echo "==> tinytap log (last 20 lines)"
tail -20 "${TT_OUT}"

echo ""
echo "==> uprobe attachment count in tinytap log"
grep -c "uprobe attached for pid" "${TT_OUT}" 2>/dev/null && true || echo "  0 (no uprobe attachments)"
