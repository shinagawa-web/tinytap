#!/usr/bin/env bash
# Start Bun.serve file server on PORT (default 8080).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-8080}"
if ! command -v bun >/dev/null 2>&1 && [ -f "$HOME/.bun/bin/bun" ]; then
    export PATH="$HOME/.bun/bin:$PATH"
fi
exec bun run "$DIR/server.js" "$PORT"
