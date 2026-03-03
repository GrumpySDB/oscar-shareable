#!/bin/bash
set -e

# --- Configuration ---
DOCKER_APP_USER="web"                   # The non-sudo user who runs rootless docker
BASE_DEPLOY_DIR="/opt/secure-uploader"  # The root of the production deployment

# --- Root Check ---
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (or via sudo)."
    exit 1
fi

echo "Hardening Secure Uploader Environment in $BASE_DEPLOY_DIR..."

# 1. Ensure user and directories exist
id -u "$DOCKER_APP_USER" &>/dev/null || useradd -m -s /bin/bash "$DOCKER_APP_USER"

mkdir -p "$BASE_DEPLOY_DIR"
chown "$DOCKER_APP_USER:$DOCKER_APP_USER" "$BASE_DEPLOY_DIR"
chmod 711 "$BASE_DEPLOY_DIR"

# 2. Copy and migrate configuration
# We assume the script is run from the root of the cloned repository
FILES_TO_MIGRATE=("docker-compose.prod.yml" "cloudflared" "nginx")

for ITEM in "${FILES_TO_MIGRATE[@]}"; do
    if [ -e "$ITEM" ]; then
        if [ "$ITEM" == "docker-compose.prod.yml" ]; then
            cp "$ITEM" "$BASE_DEPLOY_DIR/docker-compose.yml"
            chown "$DOCKER_APP_USER:$DOCKER_APP_USER" "$BASE_DEPLOY_DIR/docker-compose.yml"
            chmod 644 "$BASE_DEPLOY_DIR/docker-compose.yml"
            echo "Migrated and renamed docker-compose.prod.yml -> $BASE_DEPLOY_DIR/docker-compose.yml"
        else
            cp -r "$ITEM" "$BASE_DEPLOY_DIR/"
            chown -R "$DOCKER_APP_USER:$DOCKER_APP_USER" "$BASE_DEPLOY_DIR/$ITEM"
            # Ensure directories are traversable but files are locked down
            find "$BASE_DEPLOY_DIR/$ITEM" -type d -exec chmod 755 {} +
            find "$BASE_DEPLOY_DIR/$ITEM" -type f -exec chmod 644 {} +
            echo "Migrated directory: $ITEM"
        fi
    fi
done

cd "$BASE_DEPLOY_DIR"

# 3. Setup sub-directories
DIRS=("data/uploads" "data/profiles" "data/app_config" "secrets" "certs")
for DIR in "${DIRS[@]}"; do
    mkdir -p "$DIR"
    chown "$DOCKER_APP_USER:$DOCKER_APP_USER" "$DIR"
    chmod 755 "$DIR"
done

# 3. Provision secrets placeholder
SECRETS=(
    "secrets/jwt_secret.txt"
    "secrets/app_username.txt"
    "secrets/app_password.txt"
    "secrets/tunnel_token.txt"
    "secrets/discord_client_secret.txt"
)
for SECRET in "${SECRETS[@]}"; do
    if [ ! -f "$SECRET" ]; then
        touch "$SECRET"
        echo "Created empty secret: $SECRET"
    fi
    chown "$DOCKER_APP_USER:$DOCKER_APP_USER" "$SECRET"
    chmod 644 "$SECRET"
done

if [ ! -f ".env" ]; then
    touch .env
    chown "$DOCKER_APP_USER:$DOCKER_APP_USER" .env
    chmod 644 .env
    echo "Created empty .env"
fi

echo "Provisioning complete."
echo "ACTION REQUIRED: Populate .env and secrets/ then run the following as user '$DOCKER_APP_USER':"
echo "  cd $BASE_DEPLOY_DIR"
echo "  docker compose up -d"
