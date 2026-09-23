FROM rust:1.90-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
COPY web ./web
RUN cargo build --locked --release --bin masking-service

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 1000 -g 1000 -m 0700 /var/lib/1c-masking /run/1c-masking

COPY --from=builder --chown=1000:1000 /build/target/release/masking-service /usr/local/bin/masking-service

USER 1000:1000

ENV MASKING_DATABASE_PATH=/var/lib/1c-masking/service.sqlite3 \
    MASKING_SOCKET_PATH=/run/1c-masking/service.sock \
    MASKING_CONTROL_SOCKET_PATH=/run/1c-masking/control.sock \
    MASKING_HUMAN_BIND=0.0.0.0:8787 \
    MASKING_MANAGER_UID=1000

EXPOSE 8787

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error \
        --unix-socket /run/1c-masking/service.sock \
        http://localhost/internal/v1/health/live >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/masking-service"]
