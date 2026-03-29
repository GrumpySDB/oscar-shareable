#!/bin/bash
# scripts/dock-up.sh - Correctly launch docker compose in this environment

# 1. Source .env to get DOCKER_HOST_PATH
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# 2. Check for DOCKER_HOST_PATH
if [ -z "$DOCKER_HOST_PATH" ]; then
    echo "Error: DOCKER_HOST_PATH is not set in .env"
    exit 1
fi

# 3. Force XDG_RUNTIME_DIR to /var/run for rootful docker socket
export XDG_RUNTIME_DIR=/var/run

# 4. Run docker compose with sudo -E to preserve these exports
sudo -E docker compose up -d "$@"
