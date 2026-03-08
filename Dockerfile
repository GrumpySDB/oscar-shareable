# --- Stage 1: Frontend Build ---
FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# --- Stage 2: Backend Build ---
FROM rust:1-slim-bookworm AS backend-builder
WORKDIR /usr/src/app
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential

# Cache dependencies
COPY secure-uploader-rs/Cargo.toml ./
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy backend source
COPY secure-uploader-rs/src ./src
# Copy built frontend assets from Stage 1
COPY --from=frontend-builder /app/dist ./public

# Re-build with actual source and assets
RUN find src -type f -exec touch {} + && cargo build --release

# --- Stage 3: Runtime ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Non-root user (match UID/GID from compose or default)
ARG UID=911
ARG GID=911
RUN groupadd -g ${GID} appuser && useradd -u ${UID} -g ${GID} -s /bin/sh -m appuser

COPY --from=backend-builder /usr/src/app/target/release/secure-uploader /app/secure-uploader
COPY --from=backend-builder /usr/src/app/public /app/public

RUN chown -R appuser:appuser /app
USER appuser

ENV RUST_LOG="info,secure_uploader=debug"
CMD ["/app/secure-uploader"]
