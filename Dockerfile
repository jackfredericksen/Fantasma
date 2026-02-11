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

# Build release binary
RUN cargo build --release -p fantasma-server

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/fantasma-server /usr/local/bin/

# Copy static assets
COPY crates/fantasma-server/templates/ /app/templates/

ENV RUST_LOG=fantasma_server=info,tower_http=info
ENV FANTASMA_BIND=0.0.0.0:3000

EXPOSE 3000

CMD ["fantasma-server"]
