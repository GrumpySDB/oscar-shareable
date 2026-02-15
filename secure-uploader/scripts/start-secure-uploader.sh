#!/usr/bin/env bash
set -euo pipefail

PORT="${SECURE_UPLOADER_PORT:-}"
if [[ -z "$PORT" ]]; then
  PORT="$(shuf -i 49152-65535 -n 1)"
fi

echo "Starting secure uploader on high random host port: ${PORT}"
SECURE_UPLOADER_PORT="$PORT" docker compose up --build -d

echo
echo "Secure uploader is available at: https://localhost:${PORT}"
