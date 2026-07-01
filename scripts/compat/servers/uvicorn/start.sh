#!/usr/bin/env bash
# Start Uvicorn (ASGI) serving testdata/ on PORT (default 8080).
# Requires: pip install uvicorn
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-8080}"
exec uvicorn app:app --app-dir "$DIR" --host 0.0.0.0 --port "$PORT"
