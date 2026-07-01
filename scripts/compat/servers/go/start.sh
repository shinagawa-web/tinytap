#!/usr/bin/env bash
# Start Go net/http file server on PORT (default 8080).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../../../.." && pwd)"
PORT="${1:-8080}"
exec go run "$REPO/scripts/compat/servers/go/main.go" "$PORT"
