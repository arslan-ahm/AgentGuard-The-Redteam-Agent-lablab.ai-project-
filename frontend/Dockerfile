# Builds the SPA with Bun, then serves it with Caddy, which is also the reverse proxy
# (/api and /healthz -> backend) and terminates HTTPS when SITE_ADDRESS is a real domain.
# Build context is the repo root: docker compose build web
FROM oven/bun:1.3.13-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

FROM caddy:2.10-alpine
COPY frontend/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
