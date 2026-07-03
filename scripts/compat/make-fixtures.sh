#!/usr/bin/env bash
# Generate body-size fixtures for the server-compat exercise (#37).
# Run once before starting any server.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTDATA="$SCRIPT_DIR/../../testdata"

mkdir -p "$TESTDATA"

# print('x' * N) emits N chars + newline = N+1 bytes total.
python3 -c "print('x' * 199)"   > "$TESTDATA/small.txt"   #   200 B — comfortably within the 4096 B BPF cap (#36)
python3 -c "print('x' * 8191)"  > "$TESTDATA/medium.txt"  # 8192 B — ~2x the cap, tests truncated-but-paired
python3 -c "print('x' * 51199)" > "$TESTDATA/large.txt"   # 51200 B — forces multiple writes or sendfile

# A minimal valid 1x1 RGBA PNG (68 B) — the "Image" case (#117): confirms the
# TUI shows the binary placeholder instead of a hex/decoded dump, driven by
# the server's Content-Type: image/png response header, not by body size.
base64 -d > "$TESTDATA/image.png" <<'EOF'
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=
EOF

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
check "$TESTDATA/medium.txt" 8192
check "$TESTDATA/large.txt"  51200
check "$TESTDATA/image.png"  68
echo "==> Fixtures ready in $TESTDATA"
