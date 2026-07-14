# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=rust:1.97-bookworm
ARG RUNTIME_IMAGE=postgres:18-bookworm
ARG NODE_IMAGE=node:24-alpine

FROM ${NODE_IMAGE} AS frontend-builder
WORKDIR /app/frontend
RUN corepack enable && corepack prepare pnpm@9 --activate
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN --mount=type=cache,id=sub2api-rust-pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --prefer-offline
COPY frontend/ ./
COPY docs/legal/ /app/docs/legal/
RUN pnpm run build

FROM ${RUST_IMAGE} AS builder
WORKDIR /src

COPY backend-rust ./backend-rust

WORKDIR /src/backend-rust
RUN --mount=type=cache,id=sub2api-rust-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=sub2api-rust-target,target=/src/backend-rust/target \
    cargo build --release --locked && \
    cp target/release/sub2api-rust /tmp/sub2api-rust

FROM ${RUNTIME_IMAGE}
ARG SUB2API_BUILD_VERSION=development
WORKDIR /app
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    command -v gosu >/dev/null && \
    pg_dump --version | grep -Eq '^pg_dump \(PostgreSQL\) 18\.' && \
    pg_restore --version | grep -Eq '^pg_restore \(PostgreSQL\) 18\.' && \
    groupadd --system --gid 1000 sub2api && \
    useradd --system --uid 1000 --gid sub2api --create-home sub2api && \
    install -d -o sub2api -g sub2api -m 0750 /app/data

COPY --from=builder /tmp/sub2api-rust /usr/local/bin/sub2api-rust
COPY --from=builder /src/backend-rust/resources /app/resources
COPY --from=frontend-builder /app/frontend-dist /app/frontend
COPY --chmod=755 deploy/docker-entrypoint-rust.sh /usr/local/bin/sub2api-entrypoint

ENV FRONTEND_DIR=/app/frontend \
    SUB2API_BUILD_VERSION=${SUB2API_BUILD_VERSION}

EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:${SERVER_PORT:-8080}/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/sub2api-entrypoint"]
CMD ["/usr/local/bin/sub2api-rust"]
