#!/usr/bin/env bash
# Soak test — scenario: churn
#
# Runs tinytap against sustained HTTP connection churn (N parallel
# curl --no-keepalive workers) and samples resource metrics at a fixed
# interval. Designed to surface map, memory, and fd leaks that only appear
# under long-running load.
#
# Prerequisites:
#   - Run inside the Lima VM (eBPF requires Linux)
#   - Run `make generate` before this script (generated BPF bindings are not
#     committed; the build will fail without them)
#   - bpftool must be installed:
#       sudo apt-get install -y linux-tools-common linux-tools-$(uname -r)
#
# Usage:
#   DURATION=60  bash scripts/soak.sh   # 60 s (default) — validation run
#   DURATION=900 bash scripts/soak.sh   # 15 min — real soak
#
# Env vars:
#   DURATION         seconds to run (default: 60)
#   SAMPLE_INTERVAL  seconds between metric samples (default: 10)
#   CHURN_WORKERS    parallel curl workers (default: 5)
#   PORT             HTTP server port (default: 19080)
#   TSV_OUT          path for TSV output (default: /tmp/tinytap-soak-metrics.tsv)

set -euo pipefail

DURATION="${DURATION:-60}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-10}"
CHURN_WORKERS="${CHURN_WORKERS:-5}"
PORT="${PORT:-19080}"
TSV_OUT="${TSV_OUT:-/tmp/tinytap-soak-metrics.tsv}"

# setcap'd binaries drop capabilities on nosuid mounts (e.g. /tmp on the dev
# VM) — build into the repo root instead, same as test-e2e.sh.
TT_BIN="${PWD}/tinytap-soak"
TT_CAPS="cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog"
TT_CFG=/tmp/tinytap-soak-config.toml
TT_OUT=/tmp/tinytap-soak.log
PY_LOG=/tmp/tinytap-soak-py.log

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

# preflight_bpf_maps — resolves each expected BPF map name after tinytap has
# loaded its programs. BPF object names are kernel-truncated to 15 chars.
# Exits 1 and prints all real map names if any expected name is missing,
# converting a silent "always shows 0" failure into a loud one.
preflight_bpf_maps() {
    if ! command -v bpftool &>/dev/null; then
        echo "  WARNING: bpftool not found — BPF map columns will show N/A"
        echo "  Install: sudo apt-get install -y linux-tools-common linux-tools-\$(uname -r)"
        return
    fi
    # Expected names after kernel 15-char truncation:
    #   incoming_pending_map  → incoming_pendin
    #   drop_counters         → drop_counters  (13 chars, no truncation)
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

# count_bpf_map <name> — counts entries in a BPF hash map by (truncated) name.
# Returns 0 when the map is empty and "N/A" when bpftool is unavailable.
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

# read_drop_counters — reads the PERCPU_ARRAY drop_counters map and prints
# "ringbuf map_full" as cumulative totals summed across all CPUs.
read_drop_counters() {
    command -v bpftool &>/dev/null || { echo "N/A N/A"; return; }
    local id
    id=$(sudo bpftool map show -j 2>/dev/null | \
        jq -r '.[] | select(.name == "drop_counters") | .id' 2>/dev/null | head -1 || true)
    [[ -z "${id}" ]] && { echo "0 0"; return; }
    local dump
    dump=$(sudo bpftool map dump id "${id}" -j 2>/dev/null || echo "[]")
    local rb mf
    # bpftool -j emits both raw bytes (values[].value is a byte array) and
    # a decoded view (formatted.values[].value is an integer). Use formatted.
    rb=$(echo "${dump}" | jq '[.[0].formatted.values[].value] | add // 0' 2>/dev/null) || rb="N/A"
    mf=$(echo "${dump}" | jq '[.[1].formatted.values[].value] | add // 0' 2>/dev/null) || mf="N/A"
    echo "${rb} ${mf}"
}

# proc_cpu_ticks <pid> — prints utime+stime from /proc/PID/stat
proc_cpu_ticks() {
    local stat
    stat=$(cat /proc/"$1"/stat 2>/dev/null) || { echo 0; return; }
    local f
    read -ra f <<< "${stat}"
    echo $(( f[13] + f[14] ))
}

# ── Build ─────────────────────────────────────────────────────────────────────
echo "==> make generate (regenerates BPF bindings — requires clang-17 + libbpf)"
make generate

echo "==> building tinytap"
go build -o "${TT_BIN}" ./cmd/tinytap/

echo "==> setcap ${TT_CAPS}"
sudo setcap "${TT_CAPS}=eip" "${TT_BIN}"

# ── HTTP server ───────────────────────────────────────────────────────────────
echo "==> python3 -m http.server ${PORT}"
python3 -m http.server "${PORT}" >"${PY_LOG}" 2>&1 &
PY_PID=$!
wait_for_port localhost "${PORT}" || { echo "FAIL: http.server did not start"; exit 1; }

# ── Start tinytap ──────────────────────────────────────────────────────────────
printf 'output = "stdout"\n' >"${TT_CFG}"
: >"${TT_OUT}"
"${TT_BIN}" --config "${TT_CFG}" >"${TT_OUT}" 2>&1 &
wait_for_tinytap || { echo "FAIL: tinytap did not become ready"; cat "${TT_OUT}"; exit 1; }
TT_PID=$(pgrep -x tinytap-soak | head -1)
echo "  tinytap pid=${TT_PID}"

# ── BPF map preflight (after tinytap has loaded its programs) ─────────────────
echo "==> BPF map preflight"
preflight_bpf_maps

# ── Load generator ─────────────────────────────────────────────────────────────
echo "==> starting ${CHURN_WORKERS} curl churn workers (--no-keepalive)"
for _ in $(seq 1 "${CHURN_WORKERS}"); do
    (while true; do
        curl -fsS --no-keepalive "http://localhost:${PORT}/" -o /dev/null 2>/dev/null || true
    done) &
    CHURN_PIDS+=($!)
done

# ── Metrics TSV header ─────────────────────────────────────────────────────────
printf "elapsed_s\trss_kb\tcpu_pct\tfd_count\tincoming_pendin\tdrop_ringbuf\tdrop_map_full\tpairs_out\treqs_in\n" \
    | tee "${TSV_OUT}"

# ── Sampling state (updated each iteration) ────────────────────────────────────
PREV_TICKS=$(proc_cpu_ticks "${TT_PID}")
PREV_TS_MS=$(date +%s%3N)
CLK_TCK=$(getconf CLK_TCK 2>/dev/null || echo 100)

do_sample() {
    local elapsed=$1

    # tinytap alive check
    local alive=1
    [[ -f "/proc/${TT_PID}/status" ]] || alive=0

    # tinytap CPU%
    local cur_ticks cur_ts_ms elapsed_ms cpu_pct=0
    cur_ticks=$(proc_cpu_ticks "${TT_PID}")
    cur_ts_ms=$(date +%s%3N)
    elapsed_ms=$(( cur_ts_ms - PREV_TS_MS ))
    # Guard against negative result when the process exits (cur_ticks resets to 0).
    if [[ "${elapsed_ms}" -gt 0 && "${cur_ticks}" -ge "${PREV_TICKS}" ]]; then
        cpu_pct=$(( (cur_ticks - PREV_TICKS) * 100 * 1000 / elapsed_ms / CLK_TCK ))
    fi
    PREV_TICKS=${cur_ticks}
    PREV_TS_MS=${cur_ts_ms}

    if [[ "${alive}" -eq 0 ]]; then
        echo "WARN: tinytap-soak (pid ${TT_PID}) is no longer running at elapsed=${elapsed}s" >&2
    fi

    # process metrics
    local rss fds
    # /proc/PID/status is readable without ptrace; VmRSS is present for living processes.
    rss=$(awk '/VmRSS/{print $2}' /proc/"${TT_PID}"/status 2>/dev/null) || true
    rss=${rss:-0}
    # setcap sets dumpable=0, making /proc/PID/fd inaccessible to non-root even for the
    # same user. Use sudo to read the fd directory.
    fds=$(sudo ls /proc/"${TT_PID}"/fd 2>/dev/null | wc -l) || fds=0

    # BPF metrics
    local incoming drop_rb drop_mf
    incoming=$(count_bpf_map "incoming_pendin")
    read -r drop_rb drop_mf <<< "$(read_drop_counters)"

    # output vs input
    # pairs: JSONL lines start with '{'; log lines (Go log format) do not.
    # Use || true so grep's exit 1 (no matches) doesn't trip set -e.
    local pairs reqs
    pairs=$(grep -c '^{' "${TT_OUT}" 2>/dev/null) || true
    pairs=${pairs:-0}
    # python http.server logs one line per request to PY_LOG.
    reqs=$(grep -c '"GET\|"POST\|"HEAD' "${PY_LOG}" 2>/dev/null) || true
    reqs=${reqs:-0}

    printf "%d\t%d\t%d\t%d\t%s\t%s\t%s\t%d\t%d\n" \
        "${elapsed}" "${rss}" "${cpu_pct}" "${fds}" \
        "${incoming}" "${drop_rb}" "${drop_mf}" \
        "${pairs}" "${reqs}" \
        | tee -a "${TSV_OUT}"
}

# ── Soak loop ──────────────────────────────────────────────────────────────────
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

# Final sample at end of run
ELAPSED=$(( $(date +%s) - START ))
do_sample "${ELAPSED}"

echo
echo "==> soak complete — stopping"
cleanup
trap - EXIT

# ── Report ────────────────────────────────────────────────────────────────────
echo
echo "=== metrics ==="
column -t "${TSV_OUT}"
echo
echo "TSV saved to ${TSV_OUT}"

# ── Analysis ──────────────────────────────────────────────────────────────────
echo
echo "=== analysis ==="

FIRST=$(awk 'NR==2{print}' "${TSV_OUT}")
LAST=$(awk 'END{print}' "${TSV_OUT}")
FAILURES=0

# check_growth <label> <tsv-field> <threshold> — for gauges (RSS, fds, map
# entries): fails if last - first > threshold.
check_growth() {
    local label=$1 field=$2 threshold=$3
    local first_val last_val
    first_val=$(echo "${FIRST}" | cut -f"${field}")
    last_val=$(echo "${LAST}" | cut -f"${field}")
    if [[ "${first_val}" == "N/A" || "${last_val}" == "N/A" ]]; then
        echo "  SKIP ${label}: N/A"
        return
    fi
    local growth=$(( last_val - first_val ))
    if [[ "${growth}" -gt "${threshold}" ]]; then
        echo "  WARN ${label}: grew by ${growth} (${first_val} → ${last_val})"
        FAILURES=$(( FAILURES + 1 ))
    else
        echo "  OK   ${label}: ${first_val} → ${last_val}"
    fi
}

check_growth "RSS (KB)"        2  10000
check_growth "fd count"        4  20
check_growth "incoming_pendin" 5  20

# drop_counters are cumulative totals — check absolute final value, not delta.
for field_label in "6:drop_ringbuf" "7:drop_map_full"; do
    local_field=${field_label%%:*}
    local_label=${field_label##*:}
    final_val=$(echo "${LAST}" | cut -f"${local_field}")
    if [[ "${final_val}" == "N/A" ]]; then
        echo "  SKIP ${local_label}: N/A"
    elif [[ "${final_val}" -gt 0 ]]; then
        echo "  WARN ${local_label}: ${final_val} total drops"
        FAILURES=$(( FAILURES + 1 ))
    else
        echo "  OK   ${local_label}: 0"
    fi
done

# pair/request ratio: pairs should track requests closely.
FINAL_PAIRS=$(echo "${LAST}" | cut -f8)
FINAL_REQS=$(echo "${LAST}" | cut -f9)
if [[ "${FINAL_REQS}" -gt 0 ]]; then
    RATIO=$(( FINAL_PAIRS * 100 / FINAL_REQS ))
    if [[ "${RATIO}" -lt 90 ]]; then
        echo "  WARN pair/req ratio: ${FINAL_PAIRS}/${FINAL_REQS} (${RATIO}%) — below 90%"
        FAILURES=$(( FAILURES + 1 ))
    else
        echo "  OK   pair/req ratio: ${FINAL_PAIRS}/${FINAL_REQS} (${RATIO}%)"
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
