#!/usr/bin/env bash
# MaskedRunner demo launcher (Git Bash): builds if needed, starts API + UI,
# and leaves the server running in the foreground. Run CLI commands in another
# terminal with:  alias mr=./target/release/maskedrunner.exe
set -e
cd "$(dirname "$0")"

echo "MaskedRunner demo launcher"
if [ ! -x target/release/maskedrunner.exe ] || [ ! -x target/release/maskedrunner-api.exe ]; then
  echo "Building release binaries (first run only)..."
  cargo build --release -p maskedrunner-cli -p maskedrunner-api
fi

echo "Starting server on http://localhost:8787 (Ctrl+C to stop)..."
# open the browser once the port answers, without blocking the server
( for i in $(seq 1 20); do
    if curl -s -o /dev/null http://127.0.0.1:8787/api/spec; then
      ( command -v start >/dev/null && start "http://localhost:8787" ) 2>/dev/null || true
      break
    fi
    sleep 0.3
  done ) &

exec ./target/release/maskedrunner-api.exe
