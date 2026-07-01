#!/usr/bin/env bash
# Fire compat requests at a running server and verify response sizes.
#
# Prerequisites (in separate terminals before running this):
#   1. Start the server serving testdata/ on the target port
#      e.g.  cd testdata && python3 -m http.server 8080
#   2. Start tinytap
#      e.g.  sudo ./tinytap
#
# Usage:
#   bash scripts/compat/run.sh http://localhost:8080
set -euo pipefail

SERVER_URL="${1:?Usage: $0 <SERVER_URL>   e.g. http://localhost:8080}"
SERVER_URL="${SERVER_URL%/}"  # strip trailing slash

SMALL_EXPECTED=200
MEDIUM_EXPECTED=1024
LARGE_EXPECTED=51200

fire() {
    local label=$1 path=$2 expected=$3
    local actual
    actual=$(curl -fsSo /dev/null -w "%{size_download}" "$SERVER_URL/$path")
    if [ "$actual" -ne "$expected" ]; then
        echo "ABORT: $label — expected ${expected}B, got ${actual}B (fixture or server mismatch)" >&2
        exit 1
    fi
    printf "  OK  %-30s %6dB\n" "$label" "$actual"
}

echo "==> Firing compat requests at $SERVER_URL"
echo

fire "small.txt  (within BPF cap)"   "small.txt"  "$SMALL_EXPECTED"
fire "medium.txt (exceeds cap)"       "medium.txt" "$MEDIUM_EXPECTED"
fire "large.txt  (multi-write / sendfile)" "large.txt"  "$LARGE_EXPECTED"

echo
echo "==> All responses verified. Check tinytap TUI for captured events."
