FROM cloudflare/cloudflared:latest

# Switch to root to install envsubst (gettext-base)
USER root
RUN apt-get update && \
    apt-get install -y gettext-base && \
    rm -rf /var/lib/apt/lists/*

# Copy the template and entrypoint script
COPY config.yml.example /etc/cloudflared/config.yml.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# We run as root so we can write the config file into /etc/cloudflared/
# Cloudflared will still run its worker processes safely.
ENTRYPOINT ["/entrypoint.sh"]
