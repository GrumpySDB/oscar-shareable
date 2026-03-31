#!/bin/bash
# scripts/dock-up.sh - Robustly launch docker compose for development
set -e

# --- 1. Environment and Constants ---
WS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
XDG_RUNTIME_DIR_DEFAULT="/config/.XDG"
mkdir -p "$XDG_RUNTIME_DIR_DEFAULT"

# --- 2. Auto-discover DOCKER_HOST_PATH ---
# We need to find the host's absolute path to this directory.
# In this environment, /config is a mount from the host.
echo "Discovering host workspace path..."

# 2.1 Get the host path of /config from mountinfo
# Format: ID PARENT MAJOR:MINOR ROOT DESTINATION ...
HOST_CONFIG_ROOT=$(awk '$5 == "/config" {print $4}' /proc/self/mountinfo | head -n 1)

if [ -z "$HOST_CONFIG_ROOT" ]; then
    echo "Warning: Could not find /config in /proc/self/mountinfo. Falling back to label discovery."
    # Fallback to Docker Compose label discovery
    LABELS_JSON=$(sudo docker inspect $(hostname) --format '{{ json .Config.Labels }}' 2>/dev/null || echo "{}")
    HOST_PROJECT_DIR=$(echo "$LABELS_JSON" | jq -r '."com.docker.compose.project.working_dir" // empty')
    if [ -n "$HOST_PROJECT_DIR" ] && [ "$HOST_PROJECT_DIR" != "null" ]; then
        HOST_CONFIG_ROOT="${HOST_PROJECT_DIR}/volume/_data"
    fi
fi

if [ -n "$HOST_CONFIG_ROOT" ] && [ "$HOST_CONFIG_ROOT" != "null" ]; then
    # We must handle the /var/home vs /home symlink issue common in this environment
    if [[ "$HOST_CONFIG_ROOT" == /home/* ]]; then
        HOST_CONFIG_ROOT="/var${HOST_CONFIG_ROOT}"
    fi
    
    REL_PATH="${WS_ROOT#/config}"
    HOST_PATH="${HOST_CONFIG_ROOT}${REL_PATH}"
    echo "Detected DOCKER_HOST_PATH: $HOST_PATH"
else
    echo "Warning: Auto-detection failed. Using local workspace root (may fail volume mounts)."
    HOST_PATH="$WS_ROOT"
fi

# --- 3. Provision Missing Secrets (Empty) ---
# We must ensure secret files exist in the container directory, which 
# maps to the host directory detected above.
mkdir -p "$WS_ROOT/secrets"
SECRETS=(
    "jwt_secret.txt"
    "app_username.txt"
    "app_password.txt"
    "discord_client_secret.txt"
    "tunnel_token.txt"
)
for S in "${SECRETS[@]}"; do
    if [ ! -f "$WS_ROOT/secrets/$S" ]; then
        echo "Creating empty secret file: secrets/$S"
        touch "$WS_ROOT/secrets/$S"
        chmod 600 "$WS_ROOT/secrets/$S"
    fi
done

# --- 4. Environment Preparation ---
export DOCKER_HOST_PATH="$HOST_PATH"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$XDG_RUNTIME_DIR_DEFAULT}"
export DOCKER_SOCKET_PATH="/var/run/docker.sock"

# Verify docker socket permissions
if [ ! -S "$DOCKER_SOCKET_PATH" ]; then
    echo "Error: Docker socket not found at $DOCKER_SOCKET_PATH"
    exit 1
fi

# --- 5. Run Docker Compose ---
echo "Starting development containers (sudo docker compose up -d)..."
# We move to the workspace root to ensure docker-compose.override.yml is picked up
cd "$WS_ROOT"

# Use sudo -E to preserve the exported variables
# We pass the variables explicitly to ensure they are available to docker compose
sudo -E DOCKER_HOST_PATH="$DOCKER_HOST_PATH" \
        XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
        DOCKER_SOCKET_PATH="$DOCKER_SOCKET_PATH" \
        docker compose --profile template up -d "$@"

echo "--------------------------------------------------------"
echo "Containers started successfully."
echo "Host Path: $DOCKER_HOST_PATH"
echo "XDG Runtime: $XDG_RUNTIME_DIR"
echo "--------------------------------------------------------"
