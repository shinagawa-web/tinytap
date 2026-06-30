#!/usr/bin/env bash
# Generate body-size fixtures for the server-compat exercise (#37).
# Run once before starting any server.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTDATA="$SCRIPT_DIR/../../testdata"

mkdir -p "$TESTDATA"

# print('x' * N) emits N chars + newline = N+1 bytes total.
python3 -c "print('x' * 199)"   > "$TESTDATA/small.txt"   #   200 B — within 256 B BPF cap
python3 -c "print('x' * 1023)"  > "$TESTDATA/medium.txt"  #  1024 B — exceeds cap, tests truncation
python3 -c "print('x' * 51199)" > "$TESTDATA/large.txt"   # 51200 B — forces multiple writes or sendfile

check() {
    local file=$1 expected=$2
    local actual
    actual=$(wc -c < "$file")
    if [ "$actual" -ne "$expected" ]; then
        echo "ERROR: $(basename "$file") is $actual bytes, expected $expected" >&2
        exit 1
    fi
    printf "  OK  %-12s %6d bytes\n" "$(basename "$file")" "$actual"
}

echo "==> Fixture sizes:"
check "$TESTDATA/small.txt"  200
check "$TESTDATA/medium.txt" 1024
check "$TESTDATA/large.txt"  51200
echo "==> Fixtures ready in $TESTDATA"
