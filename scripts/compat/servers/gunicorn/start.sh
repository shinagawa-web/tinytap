#!/usr/bin/env bash
# Start Gunicorn (WSGI, sync worker) serving testdata/ on PORT (default 8080).
# Requires: pip install gunicorn
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-8080}"
exec gunicorn --chdir "$DIR" --bind "0.0.0.0:$PORT" app:app
