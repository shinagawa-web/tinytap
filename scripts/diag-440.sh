#!/usr/bin/env bash
# Diagnostic for #440, not meant to be merged. Runs the coverage test alone
# and after the rest of the package. It always exits 0: the printed counts
# are the result, and the DIAG and diag440 lines are what to read.
set -uo pipefail

bin=$1
cd cmd/tinytap || exit 1
out=$(mktemp)

run() { sudo "$bin" -test.v "$@" >"$out" 2>&1; }

failed() { grep -E '^ *--- FAIL' "$out" | sed -E 's/^ *--- FAIL: ([^ ]+).*/\1/' | sort -u | tr '\n' ' '; }

echo "==> full package, default order"
for i in 1 2; do
    run
    echo "DIAG full round=${i} failed=[$(failed)]"
    grep 'diag440' "$out" | sed -E "s/^ *[^ ]+ /full${i} /"
done

echo "==> coverage test alone"
for i in 1 2 3; do
    run -test.run '^TestDiag440_EventCoverage$'
    sed -n '/diag440/,$p' "$out" | sed -E "s/^ *[^ ]+ /alone${i} /"
done

exit 0
