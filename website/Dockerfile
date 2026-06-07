# fd0-website multistage build.
#
#   docker build -t fd0-website -f website/Dockerfile website
#   docker run --rm -p 5173:5173 fd0-website
#
# Builds the SSR bundle with Bun, then ships just the runtime: Bun
# itself + dist/ + node_modules. No source, no toolchain.

# ─── Stage 1: build ──────────────────────────────────────────────────────
FROM oven/bun:1.3-alpine AS build

WORKDIR /app

# Cache deps independently of source changes.
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY . .

ARG VERSION=dev
ENV FD0_WEBSITE_VERSION=${VERSION}

RUN bun run build

# ─── Stage 2: runtime ────────────────────────────────────────────────────
FROM oven/bun:1.3-alpine

WORKDIR /app

# Bun starts inside dist/ so `serveStatic({ root: "./public" })`
# resolves to dist/public (see package.json `start`).
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules

# Re-declare VERSION in this stage — multistage ARG scope is per-stage
# (build stage's ENV doesn't carry over). Without this, /version on the
# running container always reports "dev" regardless of the release tag.
ARG VERSION=dev
ENV FD0_WEBSITE_VERSION=${VERSION} \
    NODE_ENV=production \
    PORT=5173

EXPOSE 5173

WORKDIR /app/dist
ENTRYPOINT ["bun", "server.js"]
