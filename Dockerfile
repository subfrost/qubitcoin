# Qubitcoin multi-stage Docker build
# Build:  docker build -t qubitcoin/qubitcoin:latest .
# Run:    docker run -d -p 8333:8333 -p 8332:8332 -v qbc-data:/home/qubitcoin/.qubitcoin qubitcoin/qubitcoin:latest

# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM rust:1.86-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    clang \
    libclang-dev \
    libssl-dev \
    protobuf-compiler \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY patch/ patch/

# Exclude browser-only crates that have host-path dependencies.
# Remove them from workspace before building (they're not needed for qubitcoind).
RUN sed -i '/"crates\/qubitcoin-web-sys"/d; /"crates\/qubitcoin-indexer-web"/d; /"crates\/qubitcoin-tertiary-web"/d; /"crates\/qubitcoin-tertiary-support"/d; /"crates\/qubitcoin-sys"/d' Cargo.toml \
    && cargo build --release -p qubitcoind -p qubitcoin-cli

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create qubitcoin user
RUN groupadd -g 101 qubitcoin \
    && useradd -r -u 101 -g qubitcoin -m -d /home/qubitcoin -s /bin/bash qubitcoin

COPY --from=builder /build/target/release/qubitcoind /usr/local/bin/
COPY --from=builder /build/target/release/qubitcoin-cli /usr/local/bin/
COPY docker-entrypoint.sh /usr/local/bin/

# Bake in prebuilt indexer WASMs
COPY indexers/ /indexers/

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# P2P, RPC, ZMQ
EXPOSE 8333 8332 28332

VOLUME /home/qubitcoin/.qubitcoin

USER qubitcoin
WORKDIR /home/qubitcoin

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["qubitcoind"]
