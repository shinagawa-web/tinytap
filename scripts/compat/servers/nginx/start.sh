#!/usr/bin/env bash
# Start nginx serving testdata/ on port 8080.
# Writes a temporary nginx.conf with the correct absolute path.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../../../.." && pwd)"
TESTDATA="$REPO/testdata"
TMP_CONF="/tmp/tinytap-nginx-compat.conf"
TMP_PID="/tmp/tinytap-nginx-compat.pid"

sed "s|TESTDATA_PATH|$TESTDATA|g" "$DIR/nginx.conf" > "$TMP_CONF"

echo "==> nginx config: $TMP_CONF"
echo "==> serving: $TESTDATA"
exec nginx -c "$TMP_CONF" -g "pid $TMP_PID; daemon off;"
