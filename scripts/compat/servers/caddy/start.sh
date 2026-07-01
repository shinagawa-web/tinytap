#!/usr/bin/env bash
# Start Caddy serving testdata/ on port 8080.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../../../.." && pwd)"
TESTDATA="$REPO/testdata"
TMP_CADDYFILE="/tmp/tinytap-Caddyfile"

sed "s|TESTDATA_PATH|$TESTDATA|g" "$DIR/Caddyfile" > "$TMP_CADDYFILE"

echo "==> Caddyfile: $TMP_CADDYFILE"
echo "==> serving: $TESTDATA"
exec caddy run --config "$TMP_CADDYFILE"
