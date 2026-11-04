#!/usr/bin/env bash
# Diagnostic for #440, not meant to be merged. Runs the failing tests in
# different orders and process lifetimes. It always exits 0: the printed
# counts are the result, and the DIAG lines are what to read.
set -uo pipefail

bin=$1
cd cmd/tinytap || exit 1
out=$(mktemp)

run() { sudo "$bin" -test.v "$@" >"$out" 2>&1; }

failed() { grep -E '^ *--- FAIL' "$out" | sed -E 's/^ *--- FAIL: ([^ ]+).*/\1/' | sort -u | tr '\n' ' '; }

repeat() {
    local label=$1 n=$2 pass=0 fail=0 names=""
    shift 2
    for _ in $(seq "$n"); do
        if run "$@"; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
            names+="[$(failed)]"
        fi
    done
    echo "DIAG ${label} pass=${pass} fail=${fail} ${names}"
}

reportdrops='^TestReportDrops_RealRingbufDrop$'
loadbpf='^TestLoadBPF_DropCountsReflectsRealOverflow$'
pair='^(TestLoadBPF_DropCountsReflectsRealOverflow|TestReportDrops_RealRingbufDrop)$'
e2e='^TestE2ECapturePipeline$'

echo "==> each test alone, one process per run"
repeat alone-reportdrops 20 -test.run "$reportdrops"
repeat alone-loadbpf 20 -test.run "$loadbpf"
repeat alone-e2e 10 -test.run "$e2e"

echo "==> repeated inside one process"
run -test.run "$reportdrops" -test.count=20
echo "DIAG sameproc-reportdrops pass=$(grep -c '^--- PASS' "$out") fail=$(grep -c '^--- FAIL' "$out")"

echo "==> the two overflow tests together, both orders"
for seed in $(seq 1 20); do
    run -test.run "$pair" -test.shuffle="$seed"
    echo "DIAG pair seed=${seed} $(grep -E '^--- (PASS|FAIL)' "$out" | sed -E 's/^--- ([A-Z]+): Test([A-Za-z]+)_.*/\2=\1/' | tr '\n' ' ')"
done

echo "==> full package, default order"
for i in 1 2 3 4 5; do
    run
    echo "DIAG full round=${i} failed=[$(failed)]"
    grep 'diag440' "$out" | sed -E "s/^ *[^ ]+ /full${i} /"
done

echo "==> coverage test alone"
run -test.run '^TestDiag440_EventCoverage$'
grep 'diag440' "$out" | sed -E 's/^ *[^ ]+ /alone /'

exit 0
