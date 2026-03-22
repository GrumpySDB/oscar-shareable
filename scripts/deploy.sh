#!/bin/bash
set -e

# --- Configuration ---
DOCKER_APP_USER="web"                   # The non-sudo user who runs rootless docker
BASE_DEPLOY_DIR="/opt/secure-uploader"  # The root of the production deployment

# Calculate the rootless subuid mapped to container UID 911 for the 'web' user
# This is needed early for provisioning directories.
TARGET_UID=$(awk -F: '/^'$DOCKER_APP_USER':/ {print $2 + 910}' /etc/subuid)

# --- Root Check ---
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (or via sudo)."
    exit 1
fi

echo "Implementing Asymmetric Ownership Hardening in $BASE_DEPLOY_DIR..."

# 1. Setup Deployment Path (Root Owned)
mkdir -p "$BASE_DEPLOY_DIR"
chown root:root "$BASE_DEPLOY_DIR"
chmod 755 "$BASE_DEPLOY_DIR"

# 2. Identify Source Directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Migrating configuration from $REPO_ROOT to $BASE_DEPLOY_DIR..."

# 3. Migrate Immutable Config (Root Owned, Web Readable)
# These files define the infrastructure. Making them root-owned prevents 
# a compromised 'web' user from persisting or redirecting traffic.
ITEMS_TO_MIGRATE=("$REPO_ROOT/docker-compose.prod.yml" "$REPO_ROOT/cloudflared" "$REPO_ROOT/nginx")

for SRC in "${ITEMS_TO_MIGRATE[@]}"; do
    if [ -e "$SRC" ]; then
        ITEM_NAME=$(basename "$SRC")
        DEST="$BASE_DEPLOY_DIR/$ITEM_NAME"
        
        # Rename the production compose file during migration
        if [ "$ITEM_NAME" == "docker-compose.prod.yml" ]; then
            DEST="$BASE_DEPLOY_DIR/docker-compose.yml"
        fi
        
        cp -r "$SRC" "$DEST"
        chown -R root:root "$DEST"
        
        # Ensure directories are traversable and files are readable by web
        if [ -d "$DEST" ]; then
            find "$DEST" -type d -exec chmod 755 {} +
            find "$DEST" -type f -exec chmod 644 {} +
        else
            chmod 644 "$DEST"
        fi
        
        echo "Successfully migrated Immutable Config: $ITEM_NAME"
    else
        echo "Warning: Could not find $SRC to migrate."
    fi
done

cd "$BASE_DEPLOY_DIR"

# 4. Provision Web-Owned Directories (Data & Secrets)
# These must be accessible by the web user for the containers to function.
DIRS=("data/uploads" "data/profiles" "data/app_config" "secrets" "certs")
for DIR in "${DIRS[@]}"; do
    mkdir -p "$DIR"
    chown "$DOCKER_APP_USER:$DOCKER_APP_USER" "$DIR"
    if [[ "$DIR" == data/* ]]; then
        # SQLite requirement: Must be writable by container's subuid.
        # Since we know the TARGET_UID, we can chown it and use restrictive 770.
        # This allows the container (via owner) and the host web user (via group) to access data.
        chown "$TARGET_UID:$DOCKER_APP_USER" "$DIR"
        chmod 770 "$DIR"
    else
        # secrets/ certs/ should be entry-restricted
        chmod 750 "$DIR"
    fi
done

# 5. Provision Secrets (Web Owned, READ ONLY)
# Rootless Docker daemon (web user) MUST be able to read these to mount them.
# We set them to 400 so even the web user cannot accidentally modify them.
SECRETS=(
    "secrets/jwt_secret.txt"
    "secrets/app_username.txt"
    "secrets/app_password.txt"
    "secrets/tunnel_token.txt"
    "secrets/discord_client_secret.txt"
)
# Rootless subuid already calculated in Configuration section

for SECRET in "${SECRETS[@]}"; do
    if [ ! -f "$SECRET" ]; then
        touch "$SECRET"
        echo "Created empty secret: $SECRET"
    fi
    # Assign strict ownership to the container mapping, blocking the host web user
    chown "$TARGET_UID:$TARGET_UID" "$SECRET"
    chmod 400 "$SECRET"
done

# 6. Provision .env (Web Owned, READ ONLY)
if [ ! -f ".env" ]; then
    touch .env
    echo "Created empty .env"
fi
chown "$DOCKER_APP_USER:$DOCKER_APP_USER" .env
chmod 400 .env

echo "--------------------------------------------------------"
echo "Provisioning complete with Asymmetric Ownership."
echo "ACTION REQUIRED: Populate .env and secrets/ as root, then run as user '$DOCKER_APP_USER':"
echo "  cd $BASE_DEPLOY_DIR"
echo "  docker compose up -d"
echo "--------------------------------------------------------"
