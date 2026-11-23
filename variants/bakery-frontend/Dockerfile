# syntax=docker/dockerfile:1
# Variants of the Bakery frontend (React 19 + Vite 8).
# Build context: corpus/bakery-inventory-management/bakery-inventory-frontend

# ---------- deps: exact install from the committed lockfile ----------
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# ---------- build: production bundle; sourcemaps tell us exactly which npm packages were bundled ----------
FROM deps AS build
COPY . .
RUN npx vite build --sourcemap \
 && mkdir -p /gt \
 && cp -r dist /gt/dist-with-maps \
 && (npm ls --all --json > /gt/npm-ls-all.json || true) \
 && (npm ls --all --omit=dev --json > /gt/npm-ls-prod.json || true) \
 && find dist -name '*.map' -delete

# ---------- S2: the built bundle directory ----------
FROM scratch AS artifact
COPY --from=build /app/dist/ /dist/

# ---------- build info (ground-truth inputs) ----------
FROM scratch AS buildinfo
COPY --from=build /gt/ /

# ---------- S3: static bundle served by nginx (no node_modules in the image) ----------
FROM nginx:alpine AS s3-nginx
COPY --from=build /app/dist/ /usr/share/nginx/html/

# ---------- S3: Node dev-server image (full node_modules incl. dev dependencies) ----------
FROM deps AS s3-node
COPY . .
EXPOSE 5173
CMD ["npx", "vite", "--host", "0.0.0.0"]
