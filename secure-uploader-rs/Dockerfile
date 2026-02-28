FROM rust:1-slim-bookworm AS builder

# Create a dummy project and build dependencies to cache them
WORKDIR /usr/src/app
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential

COPY Cargo.toml ./
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

COPY src ./src
COPY public ./public

RUN find src -type f -exec touch {} + && cargo build --release

# Final runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Non-root user
ARG UID=911
ARG GID=911
RUN groupadd -g ${GID} appuser && useradd -u ${UID} -g ${GID} -s /bin/sh -m appuser

COPY --from=builder /usr/src/app/target/release/secure-uploader /app/secure-uploader
COPY --from=builder /usr/src/app/public /app/public

RUN chown -R appuser:appuser /app

USER appuser

ENV RUST_LOG="info,secure_uploader=debug"

CMD ["/app/secure-uploader"]
