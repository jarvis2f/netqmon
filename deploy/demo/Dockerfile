FROM rust:alpine AS collector-builder

RUN apk add --no-cache musl-dev protobuf-dev make gcc autoconf automake libtool pkgconf git

COPY scripts/build-ndpi.sh /tmp/build-ndpi.sh
RUN /tmp/build-ndpi.sh /usr/local
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV RUSTFLAGS="-C target-feature=-crt-static"

WORKDIR /usr/src/netqmon

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations

ARG TARGETARCH
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/src/netqmon/target \
    CARGO_TARGET_DIR="/usr/src/netqmon/target/${TARGETARCH:-local}" \
    cargo build --release --bin netqmon-collector && \
    cp "/usr/src/netqmon/target/${TARGETARCH:-local}/release/netqmon-collector" /netqmon-collector


FROM node:22-alpine AS ui-builder

WORKDIR /usr/src/netqmon

RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/controller-ui/package.json ./apps/controller-ui/package.json

RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

COPY apps/controller-ui ./apps/controller-ui

RUN pnpm --filter @netqmon/controller-ui build


FROM node:22-alpine

ARG NETQMON_DEMO_VERSION=0.1.0-demo
LABEL org.opencontainers.image.source=https://github.com/jarvis2f/netqmon
LABEL org.opencontainers.image.description="Netqmon Controller Demo"
LABEL org.opencontainers.image.version="${NETQMON_DEMO_VERSION}"

RUN apk add --no-cache ca-certificates tini tzdata wget libgcc python3 sqlite

COPY --from=collector-builder /usr/local/lib/libndpi.so* /usr/local/lib/
COPY --from=collector-builder /usr/local/share/licenses/ndpi /usr/local/share/licenses/ndpi
ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /app

COPY --from=collector-builder /netqmon-collector /usr/local/bin/netqmon-collector
COPY --from=collector-builder /usr/src/netqmon/migrations /app/migrations
COPY --from=ui-builder /usr/src/netqmon/apps/controller-ui/.next/standalone /app
COPY --from=ui-builder /usr/src/netqmon/apps/controller-ui/.next/static /app/apps/controller-ui/.next/static
COPY deploy/demo/entrypoint.sh /usr/local/bin/netqmon-demo-entrypoint
COPY tools/demo-db/generate_demo_db.py /usr/local/bin/generate-demo-db.py
COPY tools/demo-db/validate_demo_db.py /usr/local/bin/validate-demo-db.py

RUN chmod +x /usr/local/bin/netqmon-collector /usr/local/bin/netqmon-demo-entrypoint /usr/local/bin/generate-demo-db.py /usr/local/bin/validate-demo-db.py

ENV NODE_ENV=production
ENV HOSTNAME=0.0.0.0
ENV PORT=3000
ENV NETQMON_DEMO_MODE=true
ENV NETQMON_COLLECTOR_INTERNAL_ADDR=127.0.0.1:8091
ENV NETQMON_COLLECTOR_INTERNAL_URL=http://127.0.0.1:8091
ENV NETQMON_STORAGE_BACKEND=sqlite
ENV NETQMON_COLLECTOR_DATABASE_PATH=/data/netqmon.db
ENV NETQMON_DEMO_DATABASE_TEMPLATE=/demo/netqmon-demo.db
ENV NETQMON_MIGRATIONS_DIR=/app/migrations/sqlite
ENV NETQMON_COLLECTOR_GEO_DIR=/data/geo
ENV NETQMON_COLLECTOR_MAC_DATASET_PATH=/data/mac-prefixes.json

VOLUME ["/data", "/demo"]
EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
    CMD wget -q -O - http://127.0.0.1:8091/internal/health | grep -q "ok" || exit 1

ENTRYPOINT ["/sbin/tini", "--", "netqmon-demo-entrypoint"]
