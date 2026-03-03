#!/bin/bash
set -e

echo "Starting Secure Uploader Deployment..."

# 1. Define required directories
DIRS=("data/uploads" "data/profiles" "data/app_config" "secrets" "certs")

# The internal container UID/GID mapping for rootless docker 
# Usually, rootless docker maps the user's UID to 0 inside the container, but since
# our uploader and oscar containers explicitly drop to UID 911, we need to ensure
# the host directories are writable by the mapped subuid.
# For simplicity in rootless setups, we will ensure the files belong to the user executing this script,
# and we will rely on Docker's user namespace mapping. However, we will strictly lock down the host permissions.
USER_ID=$(id -u)
GROUP_ID=$(id -g)

echo "Setting up directories and enforcing strict permissions..."
for DIR in "${DIRS[@]}"; do
    if [ ! -d "$DIR" ]; then
        mkdir -p "$DIR"
        echo "Created directory: $DIR"
    fi
    # Restrict permissions: Only the owner can read/write/execute
    chmod 700 "$DIR"
done

# 2. Define required secrets
SECRETS=(
    "secrets/jwt_secret.txt"
    "secrets/app_username.txt"
    "secrets/app_password.txt"
    "secrets/tunnel_token.txt"
    "secrets/discord_client_secret.txt"
)

echo "Setting up secrets..."
for SECRET in "${SECRETS[@]}"; do
    if [ ! -f "$SECRET" ]; then
        touch "$SECRET"
        echo "Created empty secret file: $SECRET. PLEASE FILL THIS IN."
    fi
    # Strict permissions for secrets: read/write only by owner
    chmod 600 "$SECRET"
done

if [ ! -f ".env" ]; then
    echo "Creating empty .env file..."
    touch .env
    chmod 600 .env
    echo "PLEASE FILL IN THE .env FILE."
fi

# 3. Prompt for GitHub Container Registry Login if not logged in
if ! docker info | grep -q 'ghcr.io'; then
    echo "You do not appear to be logged into the GitHub Container Registry."
    echo "Please log in using your GitHub username and a Personal Access Token (PAT) with read:packages access."
    # We allow this to fail slightly gracefully if the user wants to cancel
    docker login ghcr.io || echo "Warning: Login failed or cancelled. Pulling images might fail if repo is private."
fi

echo "Pulling latest images..."
# The user's settings state to use `sudo docker compose`
sudo docker compose -f docker-compose.prod.yml pull

echo "Starting services..."
sudo docker compose -f docker-compose.prod.yml up -d --remove-orphans

echo "Deployment complete. Inspect logs with: sudo docker compose -f docker-compose.prod.yml logs -f"
