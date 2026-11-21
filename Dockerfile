# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Hardened multi-stage Dockerfile for octo-server.
#
# Build args (documented):
#   RUST_VERSION  Rust toolchain image tag for the builder stage.
#                 Default: 1.84.1 (keep in sync with rust-toolchain.toml).
#   BIN           Name of the server binary produced by the workspace crate.
#                 Default: octo-server.
#   APP_UID       UID of the non-root runtime user (distroless "nonroot").
#                 Default: 65532.
#   APP_GID       GID of the non-root runtime user (distroless "nonroot").
#                 Default: 65532.
#
# The final image is based on distroless (no shell, no package manager),
# runs as a non-root user, and is read-only-rootfs friendly: it writes
# nothing outside of /tmp (mount a tmpfs there if the app needs scratch
# space). A HEALTHCHECK probes /health using the binary's own health probe
# (no curl/wget/shell available in the final image).
# ---------------------------------------------------------------------------

ARG RUST_VERSION=1.84.1

# ------------------------------- builder -----------------------------------
FROM rust:${RUST_VERSION}-bookworm AS builder

# Re-declare build args used in this stage.
ARG BIN=octo-server

# Fail fast on warnings-as-errors style builds and keep output deterministic.
ENV CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-C strip=symbols"

WORKDIR /src

# Copy the whole workspace. A dependency-caching layer is intentionally
# omitted to keep the build simple and correct; add cargo-chef here if
# build times become a concern.
COPY . .

# Build only the server crate in release mode, honoring the lockfile.
RUN cargo build --release --locked -p "${BIN}" \
    && install -D -m 0755 "target/release/${BIN}" /out/bin/octo-server

# ------------------------------- runtime -----------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Re-declare build args used in this stage.
ARG APP_UID=65532
ARG APP_GID=65532

# Distroless cc-debian12 already ships CA certificates and glibc runtime
# libraries; only the binary is copied in. No shell or package manager exists.
COPY --from=builder --chown=${APP_UID}:${APP_GID} /out/bin/octo-server /usr/local/bin/octo-server

# Run as the unprivileged nonroot user (UID/GID 65532).
USER ${APP_UID}:${APP_GID}

# The server listens on 8080 by default.
EXPOSE 8080

# Read-only-rootfs friendly: point any writable scratch space at /tmp.
# Mount a tmpfs at /tmp when running with --read-only.
ENV TMPDIR=/tmp

# Distroless-compatible healthcheck: invoke the binary's own health probe
# against /health. No shell, curl, or wget is available in the final image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/octo-server", "healthcheck", "--url", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["/usr/local/bin/octo-server"]