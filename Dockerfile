# syntax=docker/dockerfile:1
# Multi-Stage: build (TS) → deps-prod (semver) → runner (node24-alpine + trivy).
# Gotcha-Vermerk: aquasec/trivy:0.68.0 existiert auf Docker Hub MAHR (404, Tags
# rotieren) — gepinnt ist 0.76.1 (21.10.2026), bei Upgrade unten anpassen.

FROM node:24.22.2-alpine3.24 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,id=npm,target=/root/.npm npm ci
COPY tsconfig.json ./
COPY src ./src
RUN ./node_modules/.bin/tsc

FROM node:24.22.2-alpine3.24 AS deps-prod
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,id=npm,target=/root/.npm npm ci --omit=dev

FROM node:24.22.2-alpine3.24 AS runner
ENV NODE_ENV=production
ENV TZ=Europe/Berlin
ENV TRIVY_CACHE_DIR=/app/.cache/trivy
COPY --from=aquasec/trivy:0.76.1 /usr/local/bin/trivy /usr/local/bin/trivy
# TZ=Europe/Berlin: Busybox-crond löst Zeitzonen via zoneinfo auf → tzdata nötig
RUN apk add --no-cache tzdata
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=deps-prod /app/node_modules ./node_modules
COPY bin ./bin
# reports/logs/cache/crontabs müssen node gehören (Volumes mounten auf dieselben Pfade)
RUN mkdir -p /app/reports /app/logs /app/.cache/trivy /app/crontabs /app/tmp \
  && chown -R node:node /app
USER node
# HEALTHCHECK ohne HTTP: Heartbeat-Alter (Spec-Angabe, 48h Toleranz für Cron-Skip)
HEALTHCHECK --interval=15m --timeout=10s --start-period=2m --retries=3 \
  CMD test $(( $(date +%s) - $(stat -c %Y /app/reports/.heartbeat 2>/dev/null || echo 0) )) -lt 172800
ENTRYPOINT ["/bin/sh", "/app/bin/entrypoint.sh"]
