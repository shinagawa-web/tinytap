#!/usr/bin/env bash
# Start Python http.server serving testdata/ on PORT (default 8080).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../../../.." && pwd)"
PORT="${1:-8080}"
exec python3 -m http.server "$PORT" --directory "$REPO/testdata"
