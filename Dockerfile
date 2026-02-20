# Build stage
FROM rust:1.75-bookworm as builder

WORKDIR /app

# Install dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY circuits/ circuits/
COPY scripts/ scripts/

# Build release binaries
RUN cargo build --release -p fantasma-server -p fantasma-cli

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /app/target/release/fantasma-server /usr/local/bin/
COPY --from=builder /app/target/release/fantasma-cli /usr/local/bin/

# Copy static assets and migrations
COPY crates/fantasma-server/templates/ /app/templates/
COPY crates/fantasma-db/migrations/ /app/migrations/

ENV RUST_LOG=fantasma_server=info,tower_http=info
ENV FANTASMA_BIND=0.0.0.0:3000

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["fantasma-server"]
