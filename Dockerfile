# syntax=docker/dockerfile:1

# The UI build is architecture-independent, so build it once on the builder host.
FROM --platform=$BUILDPLATFORM node:26-bookworm-slim AS web-build
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
COPY shared /app/shared
ARG VITE_BASE_PATH=/
ARG VITE_HIDDEN_USER_CLAIMS=
ENV VITE_BASE_PATH=${VITE_BASE_PATH} \
    VITE_HIDDEN_USER_CLAIMS=${VITE_HIDDEN_USER_CLAIMS}
RUN npm run build

# This stage follows the requested target platform. The publishing workflow
# builds for the native architecture of its GitHub-hosted runner.
FROM rust:1.98.1-bookworm AS rust-build
ARG HANKO_VERSION=
ARG HANKO_GIT_COMMIT=
ARG HANKO_BUILD_DATE=
ENV HANKO_VERSION=${HANKO_VERSION} \
    HANKO_GIT_COMMIT=${HANKO_GIT_COMMIT} \
    HANKO_BUILD_DATE=${HANKO_BUILD_DATE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY shared ./shared
COPY --from=web-build /app/web/dist ./web/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked \
    && install -D /build/target/release/hanko /out/hanko

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 hanko \
    && useradd --system --uid 10001 --gid hanko --home-dir /data --create-home hanko
WORKDIR /app
COPY --from=rust-build /out/hanko /usr/local/bin/hanko
COPY --from=web-build /app/web/dist ./web/dist
RUN chown -R 10001:10001 /data
ENV BIND_ADDRESS=0.0.0.0:38013 \
    DATABASE_URL=sqlite:///data/hanko.sqlite?mode=rwc \
    RUST_LOG=info
EXPOSE 38013
VOLUME ["/data"]
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/hanko"]
