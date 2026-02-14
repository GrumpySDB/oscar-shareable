FROM node:20-alpine

# Set working directory
WORKDIR /app

# Install openssl for self-signed cert generation
RUN apk add --no-cache openssl

# Create non-root user 'oscar' UID/GID 2000
RUN addgroup -g 911 oscar && adduser -D -u 911 -G oscar oscar

# Copy dependencies first (for caching)
COPY package*.json ./
RUN npm install --production

# Copy app code
COPY . .

# Create folders for uploads, database, and certs; generate certs at build time
RUN mkdir -p uploads db certs \
    && openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
      -subj "/CN=localhost" \
      -keyout certs/key.pem \
      -out certs/cert.pem \
    && chown -R oscar:oscar uploads db certs

# Expose port
EXPOSE 3000

# Run as non-root
USER oscar

# Start the server
CMD ["node", "server.js"]
