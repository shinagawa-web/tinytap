#!/usr/bin/env bash
# Start Axum (Rust/hyper) file server on PORT (default 8080).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-8080}"
if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi
exec cargo run --manifest-path "$DIR/Cargo.toml" --release -- "$PORT"
