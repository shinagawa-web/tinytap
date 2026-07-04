#!/usr/bin/env bash
# Start nginx serving testdata/ on port 8080: static (root /) + reverse
# proxy (/proxy/ -> BACKEND_PORT) + in-memory (/hello).
# Writes a temporary nginx.conf with the correct absolute path.
#
# Usage (all positional):
#   bash start.sh [on|off] [BACKEND_PORT] [on|off]
#                  sendfile              tcp_nopush
# e.g. `bash start.sh off 8081 on`
#
# /proxy/ only works once a backend server (e.g. `python3 -m http.server
# BACKEND_PORT --directory testdata`) is listening on BACKEND_PORT.
set -euo pipefail

SENDFILE="${1:-on}"
BACKEND_PORT="${2:-8081}"
TCP_NOPUSH="${3:-off}"

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../../../.." && pwd)"
TESTDATA="$REPO/testdata"
TMP_CONF="/tmp/tinytap-nginx-compat.conf"
TMP_PID="/tmp/tinytap-nginx-compat.pid"

sed \
    -e "s|TESTDATA_PATH|$TESTDATA|g" \
    -e "s|SENDFILE_MODE|$SENDFILE|g" \
    -e "s|TCP_NOPUSH_MODE|$TCP_NOPUSH|g" \
    -e "s|BACKEND_PORT|$BACKEND_PORT|g" \
    "$DIR/nginx.conf" > "$TMP_CONF"

echo "==> nginx config: $TMP_CONF (sendfile=$SENDFILE tcp_nopush=$TCP_NOPUSH backend=:$BACKEND_PORT)"
echo "==> serving: $TESTDATA"
exec nginx -c "$TMP_CONF" -g "pid $TMP_PID; daemon off;"
