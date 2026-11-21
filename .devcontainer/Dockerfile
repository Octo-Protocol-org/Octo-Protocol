FROM rust:1.84.1-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        pkg-config \
        libssl-dev \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install `just` from the official prebuilt binaries.
RUN curl -fsSL https://just.systems/install.sh | bash -s -- --to /usr/local/bin

# Ensure the Rust toolchain pinned by rust-toolchain.toml (1.84.1) is available.
RUN rustup toolchain install 1.84.1 \
    && rustup component add rustfmt clippy --toolchain 1.84.1

WORKDIR /workspace