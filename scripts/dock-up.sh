#!/bin/bash
# scripts/dock-up.sh - Correctly launch docker compose in this environment

# 1. Source .env to get DOCKER_HOST_PATH and other vars
if [ -f .env ]; then
    # Filter out comments and blank lines, then export each line
    while IFS= read -r line || [ -n "$line" ]; do
        # Strip comments and trim whitespace
        clean_line=$(echo "$line" | sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//')
        if [ -n "$clean_line" ]; then
            export "$clean_line"
        fi
    done < .env
fi

# 2. Check and Validate DOCKER_HOST_PATH
# If DOCKER_HOST_PATH is missing or seems to be a container-local path in a DinD environment, try to fix it.
if [ -z "$DOCKER_HOST_PATH" ] || [[ "$DOCKER_HOST_PATH" == /config* ]]; then
    # In many of our dev environments, /config is a host-mounted volume.
    # We can try to find its source by inspecting our own container.
    DETECTED_PATH=$(sudo docker inspect $(hostname) --format '{{ range .Mounts }}{{ if eq .Destination "/config" }}{{ .Source }}{{ end }}{{ end }}' 2>/dev/null)
    if [ -n "$DETECTED_PATH" ]; then
        # Append the relative subpath if we are in a subfolder like /config/dev/oscar-shareable
        SUBPATH=${PWD#/config}
        export DOCKER_HOST_PATH="${DETECTED_PATH}${SUBPATH}"
        echo "Auto-detected DOCKER_HOST_PATH: $DOCKER_HOST_PATH"
    fi
fi

if [ -z "$DOCKER_HOST_PATH" ]; then
    echo "Error: DOCKER_HOST_PATH is not set and could not be auto-detected."
    exit 1
fi

# 3. Force XDG_RUNTIME_DIR to /var/run for rootful docker socket if not explicitly overridden
if [ -z "$XDG_RUNTIME_DIR" ] || [[ "$XDG_RUNTIME_DIR" == /config* ]]; then
    export XDG_RUNTIME_DIR=/var/run
fi
# Export DOCKER_SOCKET_PATH for use in docker-compose.yml
export DOCKER_SOCKET_PATH="${XDG_RUNTIME_DIR}/docker.sock"
echo "Using DOCKER_SOCKET_PATH: $DOCKER_SOCKET_PATH"

# 4. Run docker compose with sudo -E to preserve these exports
sudo -E docker compose up -d "$@"
