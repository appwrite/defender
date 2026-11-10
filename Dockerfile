# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# --- compile ---------------------------------------------------------------
FROM rust:1.83-bookworm@sha256:a45bf1f5d9af0a23b26703b3500d70af1abff7f984a7abef5a104b42c02a292b AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY benches ./benches
COPY tests ./tests
RUN cargo build --release --locked 2>/dev/null || cargo build --release

# --- official virus DBs (baked into the image) -----------------------------
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS db
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/download-db.sh /download-db.sh
RUN chmod +x /download-db.sh && /download-db.sh /var/lib/defender/db

# --- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /var/lib/defender --shell /usr/sbin/nologin defender

COPY --from=builder /src/target/release/defender /usr/local/bin/defender
COPY --from=db /var/lib/defender/db /var/lib/defender/db
COPY scripts/download-db.sh /usr/local/bin/download-db.sh

RUN chown -R defender:defender /var/lib/defender \
    && chmod +x /usr/local/bin/download-db.sh

ENV DEFENDER_LISTEN=0.0.0.0:8080 \
    DEFENDER_DB_DIR=/var/lib/defender/db \
    DEFENDER_UPDATE_INTERVAL_SECS=3600 \
    DEFENDER_MAX_BYTES=67108864 \
    DEFENDER_USER_AGENT="ClamAV/1.4.2 (defender; docker)" \
    RUST_LOG=info \
    MALLOC_CONF=background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000

USER defender
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/defender"]
