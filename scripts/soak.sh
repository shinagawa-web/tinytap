#!/usr/bin/env bash

set -euo pipefail

DURATION="${DURATION:-60}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-10}"
CHURN_WORKERS="${CHURN_WORKERS:-5}"
SLEEP_BETWEEN_REQS="${SLEEP_BETWEEN_REQS:-0}"
PORT="${PORT:-19080}"
TSV_OUT="${TSV_OUT:-/tmp/tinytap-soak-metrics.tsv}"
MD_OUT="${MD_OUT:-/tmp/tinytap-soak-metrics.md}"

TT_BIN="${PWD}/tinytap-soak"
TT_CAPS="cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog"
TT_CFG=/tmp/tinytap-soak-config.toml
TT_OUT=/tmp/tinytap-soak.log
PY_LOG=/tmp/tinytap-soak-py.log
CURL_TIME_LOG=/tmp/tinytap-soak-curl-times.log

TT_PID=""
PY_PID=""
CHURN_PIDS=()

cleanup() {
    pkill -INT -x tinytap-soak 2>/dev/null || true
    [[ -n "${PY_PID:-}" ]] && kill "${PY_PID}" 2>/dev/null || true
    for pid in "${CHURN_PIDS[@]+"${CHURN_PIDS[@]}"}"; do
        kill "${pid}" 2>/dev/null || true
        pkill -P "${pid}" 2>/dev/null || true
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

wait_for_tinytap() {
    for _ in $(seq 1 50); do
        if grep -q "tinytap running" "${TT_OUT}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

preflight_bpf_maps() {
    if ! command -v bpftool &>/dev/null; then
        echo "  WARNING: bpftool not found — BPF map columns will show N/A"
        echo "  Install: sudo apt-get install -y linux-tools-common linux-tools-\$(uname -r)"
        return
    fi
    if ! command -v jq &>/dev/null; then
        echo "  WARNING: jq not found — BPF map columns will show N/A"
        return
    fi
    local -a expected=("incoming_pendin" "drop_counters")
    local all_names
    all_names=$(sudo bpftool map show -j 2>/dev/null | jq -r '.[].name' 2>/dev/null || true)
    local missing=0
    for name in "${expected[@]}"; do
        if ! echo "${all_names}" | grep -qx "${name}"; then
            echo "  MISSING expected BPF map: '${name}'"
            missing=1
        fi
    done
    if [[ "${missing}" -ne 0 ]]; then
        echo "  Actual map names from bpftool:"
        echo "${all_names}" | sed 's/^/    /'
        echo "FAIL: expected BPF maps not found — check name truncation against kernel version"
        exit 1
    fi
    echo "  BPF maps verified: ${expected[*]}"
}

count_bpf_map() {
    local name=$1
    command -v bpftool &>/dev/null || { echo "N/A"; return; }
    local ids
    ids=$(sudo bpftool map show -j 2>/dev/null | \
        jq -r ".[] | select(.name == \"${name}\") | .id" 2>/dev/null || true)
    [[ -z "${ids}" ]] && { echo "0"; return; }
    local total=0
    while IFS= read -r id; do
        local n
        n=$(sudo bpftool map dump id "${id}" -j 2>/dev/null | jq 'length' 2>/dev/null) || n=0
        total=$((total + n))
    done <<< "${ids}"
    echo "${total}"
}

read_drop_counters() {
    command -v bpftool &>/dev/null || { echo "N/A N/A"; return; }
    local id
    id=$(sudo bpftool map show -j 2>/dev/null | \
        jq -r '.[] | select(.name == "drop_counters") | .id' 2>/dev/null | head -1 || true)
    [[ -z "${id}" ]] && { echo "0 0"; return; }
    local dump
    dump=$(sudo bpftool map dump id "${id}" -j 2>/dev/null || echo "[]")
    local rb mf
    rb=$(echo "${dump}" | jq '[.[0].formatted.values[].value] | add // 0' 2>/dev/null) || rb="N/A"
    mf=$(echo "${dump}" | jq '[.[1].formatted.values[].value] | add // 0' 2>/dev/null) || mf="N/A"
    echo "${rb} ${mf}"
}

proc_cpu_ticks() {
    local stat
    stat=$(cat /proc/"$1"/stat 2>/dev/null) || { echo 0; return; }
    local f
    read -ra f <<< "${stat}"
    echo $(( f[13] + f[14] ))
}

echo "==> make generate (regenerates BPF bindings — requires clang-17 + libbpf)"
make generate

echo "==> building tinytap"
go build -o "${TT_BIN}" ./cmd/tinytap/

echo "==> setcap ${TT_CAPS}"
sudo setcap "${TT_CAPS}=eip" "${TT_BIN}"

echo "==> python3 -m http.server ${PORT}"
python3 -m http.server "${PORT}" >"${PY_LOG}" 2>&1 &
PY_PID=$!
wait_for_port localhost "${PORT}" || { echo "FAIL: http.server did not start"; exit 1; }

printf 'output = "stdout"\n' >"${TT_CFG}"
: >"${TT_OUT}"
"${TT_BIN}" --config "${TT_CFG}" >"${TT_OUT}" 2>&1 &
TT_PID=$!
wait_for_tinytap || { echo "FAIL: tinytap did not become ready"; cat "${TT_OUT}"; exit 1; }
echo "  tinytap pid=${TT_PID}"

echo "==> BPF map preflight"
preflight_bpf_maps

echo "==> starting ${CHURN_WORKERS} curl churn workers (--no-keepalive, sleep=${SLEEP_BETWEEN_REQS}s)"
for _ in $(seq 1 "${CHURN_WORKERS}"); do
    (while true; do
        t=$(curl -fsS --no-keepalive "http://localhost:${PORT}/" -o /dev/null \
            -w "%{time_total}" 2>/dev/null) || true
        echo "${t:-0}" >> "${CURL_TIME_LOG}"
        [[ "${SLEEP_BETWEEN_REQS}" != "0" ]] && sleep "${SLEEP_BETWEEN_REQS}"
    done) &
    CHURN_PIDS+=($!)
done

printf "elapsed_s\trss_kb\tcpu_pct\tfd_count\tincoming_pendin\tdrop_ringbuf\tdrop_map_full\tpairs_out\treqs_in\tsys_cpu_pct\tcurl_avg_ms\n" \
    | tee "${TSV_OUT}"

: >"${CURL_TIME_LOG}"
PREV_TICKS=$(proc_cpu_ticks "${TT_PID}")
PREV_TS_MS=$(date +%s%3N)
CLK_TCK=$(getconf CLK_TCK 2>/dev/null || echo 100)
read -r PREV_SYS_TOTAL PREV_SYS_IDLE <<< "$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5+$6}' /proc/stat)"
PREV_CURL_COUNT=0
PREV_CURL_SUM_MS=0

do_sample() {
    local elapsed=$1

    local alive=1
    [[ -f "/proc/${TT_PID}/status" ]] || alive=0

    local cur_ticks cur_ts_ms elapsed_ms cpu_pct=0
    cur_ticks=$(proc_cpu_ticks "${TT_PID}")
    cur_ts_ms=$(date +%s%3N)
    elapsed_ms=$(( cur_ts_ms - PREV_TS_MS ))
    if [[ "${elapsed_ms}" -gt 0 && "${cur_ticks}" -ge "${PREV_TICKS}" ]]; then
        cpu_pct=$(( (cur_ticks - PREV_TICKS) * 100 * 1000 / elapsed_ms / CLK_TCK ))
    fi
    PREV_TICKS=${cur_ticks}
    PREV_TS_MS=${cur_ts_ms}

    if [[ "${alive}" -eq 0 ]]; then
        echo "WARN: tinytap-soak (pid ${TT_PID}) is no longer running at elapsed=${elapsed}s" >&2
    fi

    local rss fds
    rss=$(awk '/VmRSS/{print $2}' /proc/"${TT_PID}"/status 2>/dev/null) || true
    rss=${rss:-0}
    fds=$(sudo ls /proc/"${TT_PID}"/fd 2>/dev/null | wc -l) || fds=0

    local incoming drop_rb drop_mf
    incoming=$(count_bpf_map "incoming_pendin")
    read -r drop_rb drop_mf <<< "$(read_drop_counters)"

    local pairs reqs
    pairs=$(grep -c '^{' "${TT_OUT}" 2>/dev/null) || true
    pairs=${pairs:-0}
    reqs=$(grep -cE '"GET|"POST|"HEAD' "${PY_LOG}" 2>/dev/null) || true
    reqs=${reqs:-0}

    local sys_total sys_idle sys_cpu_pct=0
    read -r sys_total sys_idle <<< "$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5+$6}' /proc/stat)"
    local sys_delta_total=$(( sys_total - PREV_SYS_TOTAL ))
    local sys_delta_idle=$(( sys_idle - PREV_SYS_IDLE ))
    if [[ "${sys_delta_total}" -gt 0 ]]; then
        sys_cpu_pct=$(( (sys_delta_total - sys_delta_idle) * 100 / sys_delta_total ))
    fi
    PREV_SYS_TOTAL=${sys_total}
    PREV_SYS_IDLE=${sys_idle}

    local curl_count curl_sum_ms curl_avg_ms=0
    curl_count=$(wc -l < "${CURL_TIME_LOG}" 2>/dev/null) || curl_count=0
    curl_sum_ms=$(awk '{s+=$1} END{printf "%d", s*1000+0.5}' "${CURL_TIME_LOG}" 2>/dev/null) || curl_sum_ms=0
    local delta_curl_count=$(( curl_count - PREV_CURL_COUNT ))
    local delta_curl_sum=$(( curl_sum_ms - PREV_CURL_SUM_MS ))
    if [[ "${delta_curl_count}" -gt 0 ]]; then
        curl_avg_ms=$(( delta_curl_sum / delta_curl_count ))
    fi
    PREV_CURL_COUNT=${curl_count}
    PREV_CURL_SUM_MS=${curl_sum_ms}

    printf "%d\t%d\t%d\t%d\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n" \
        "${elapsed}" "${rss}" "${cpu_pct}" "${fds}" \
        "${incoming}" "${drop_rb}" "${drop_mf}" \
        "${pairs}" "${reqs}" "${sys_cpu_pct}" "${curl_avg_ms}" \
        | tee -a "${TSV_OUT}"
}

echo "==> sampling every ${SAMPLE_INTERVAL}s for ${DURATION}s"
START=$(date +%s)
NEXT_SAMPLE=0

while true; do
    ELAPSED=$(( $(date +%s) - START ))
    [[ "${ELAPSED}" -ge "${DURATION}" ]] && break
    if [[ "${ELAPSED}" -ge "${NEXT_SAMPLE}" ]]; then
        do_sample "${ELAPSED}"
        NEXT_SAMPLE=$(( NEXT_SAMPLE + SAMPLE_INTERVAL ))
    fi
    sleep 1
done

ELAPSED=$(( $(date +%s) - START ))
do_sample "${ELAPSED}"

echo
echo "==> soak complete — stopping"
cleanup
trap - EXIT

echo
echo "=== metrics ==="
column -t "${TSV_OUT}"
echo
echo "TSV: ${TSV_OUT}"

{
    awk -F'\t' 'BEGIN{
        print "## Process / system\n"
        print "| elapsed_s | rss_kb | cpu_pct | fd_count | sys_cpu_pct |"
        print "|--:|--:|--:|--:|--:|"
    } NR>1 {print "| "$1" | "$2" | "$3" | "$4" | "$10" |"}' "${TSV_OUT}"
    printf "\n"
    awk -F'\t' 'BEGIN{
        print "## Traffic / BPF\n"
        print "| elapsed_s | incoming_pendin | drop_ringbuf | drop_map_full | pairs_out | reqs_in | curl_avg_ms |"
        print "|--:|--:|--:|--:|--:|--:|--:|"
    } NR>1 {print "| "$1" | "$5" | "$6" | "$7" | "$8" | "$9" | "$11" |"}' "${TSV_OUT}"
} > "${MD_OUT}"
echo "MD:  ${MD_OUT}"

echo
echo "=== analysis ==="

FIRST=$(awk 'NR==2{print}' "${TSV_OUT}")
LAST=$(awk 'END{print}' "${TSV_OUT}")
FAILURES=0

LAST_ALIVE=$(awk -F'\t' 'NR>1 && $2+0>0 {row=$0} END{print row}' "${TSV_OUT}")
LAST_ALIVE_EL=$(echo "${LAST_ALIVE}" | cut -f1)

check_growth() {
    local label=$1 field=$2 threshold=$3
    local first_row=${4:-${FIRST}}
    local last_row=${5:-${LAST}}
    local first_val last_val
    first_val=$(echo "${first_row}" | cut -f"${field}")
    last_val=$(echo "${last_row}" | cut -f"${field}")
    if [[ "${first_val}" == "N/A" || "${last_val}" == "N/A" || -z "${first_val}" || -z "${last_val}" ]]; then
        echo "  ${label}: N/A"
        return
    fi
    local growth=$(( last_val - first_val ))
    if [[ "${growth}" -gt "${threshold}" ]]; then
        echo "  ${label}: grew by ${growth} (${first_val} → ${last_val})"
        FAILURES=$(( FAILURES + 1 ))
    else
        echo "  ${label}: ${first_val} → ${last_val}"
    fi
}

if [[ -z "${LAST_ALIVE}" ]]; then
    echo "  tinytap-soak: died before first sample"
    FAILURES=$(( FAILURES + 1 ))
elif [[ "${LAST_ALIVE_EL:-0}" -lt "${DURATION}" ]]; then
    echo "  tinytap-soak: last alive at elapsed=${LAST_ALIVE_EL}s, died before ${DURATION}s"
    FAILURES=$(( FAILURES + 1 ))
else
    echo "  tinytap-soak: alive throughout"
fi

if [[ -n "${LAST_ALIVE}" ]]; then
    check_growth "RSS (KB)"        2  10000 "${FIRST}" "${LAST_ALIVE}"
    check_growth "fd count"        4  20    "${FIRST}" "${LAST_ALIVE}"
    check_growth "incoming_pendin" 5  20    "${FIRST}" "${LAST_ALIVE}"
fi

MAX_DROP_RB=$(awk -F'\t' 'NR>1 && $6~/^[0-9]+$/ {if ($6+0>max) max=$6+0} END{print max+0}' "${TSV_OUT}")
MAX_DROP_MF=$(awk -F'\t' 'NR>1 && $7~/^[0-9]+$/ {if ($7+0>max) max=$7+0} END{print max+0}' "${TSV_OUT}")
if [[ "${MAX_DROP_RB:-0}" -gt 0 ]]; then
    echo "  drop_ringbuf: max ${MAX_DROP_RB} during run"
    FAILURES=$(( FAILURES + 1 ))
else
    echo "  drop_ringbuf: 0"
fi
if [[ "${MAX_DROP_MF:-0}" -gt 0 ]]; then
    echo "  drop_map_full: max ${MAX_DROP_MF} during run"
    FAILURES=$(( FAILURES + 1 ))
else
    echo "  drop_map_full: 0"
fi

FINAL_PAIRS=$(echo "${LAST}" | cut -f8)
FINAL_REQS=$(echo "${LAST}" | cut -f9)
if [[ "${FINAL_REQS:-0}" -gt 0 ]]; then
    RATIO=$(( FINAL_PAIRS * 100 / FINAL_REQS ))
    if [[ "${RATIO}" -lt 90 ]]; then
        echo "  pair/req ratio: ${FINAL_PAIRS}/${FINAL_REQS} (${RATIO}%) — below 90%"
        FAILURES=$(( FAILURES + 1 ))
    else
        echo "  pair/req ratio: ${FINAL_PAIRS}/${FINAL_REQS} (${RATIO}%)"
    fi
fi

echo
if [[ "${FAILURES}" -eq 0 ]]; then
    echo "PASS"
    exit 0
else
    echo "WARN: ${FAILURES} check(s) flagged — review the TSV curves above"
    echo
    echo "=== tinytap log (last 30 lines) ==="
    tail -30 "${TT_OUT}"
    exit 1
fi
