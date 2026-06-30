#!/usr/bin/env bash
# Start Node.js http file server on PORT (default 8080).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-8080}"
exec node "$DIR/server.js" "$PORT"
