#!/bin/bash
set -e

# Substitute environment variables in the template and output to the real config path
envsubst < /etc/cloudflared/config.yml.template > /etc/cloudflared/config.yml

# Execute the original cloudflared command pass through from docker-compose
exec cloudflared "$@"
