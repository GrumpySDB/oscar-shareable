FROM node:20-alpine

# Set working directory
WORKDIR /app

# Create non-root user 'oscar' UID/GID 2000
RUN addgroup -g 911 oscar && adduser -D -u 911 -G oscar oscar

# Copy dependencies first (for caching)
COPY package*.json ./
RUN npm install --production

# Copy app code
COPY . .

# Create folders for uploads, database, and certs
RUN mkdir -p uploads db certs \
    && chown -R oscar:oscar uploads db certs

# Expose port
EXPOSE 3000

# Run as non-root
USER oscar

# Start the server
CMD ["node", "server.js"]
