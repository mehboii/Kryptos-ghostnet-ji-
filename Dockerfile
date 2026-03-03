# ============================================
# GhostNet — Multi-Stage Docker Build
# ============================================
# Single image, multiple services via docker-compose
# Node.js 20 on Alpine for minimal footprint
# ============================================

# ── Stage 1: Base ────────────────────────────
FROM node:20-alpine AS base

# Install build tools needed for native modules (bcrypt, sqlite3)
RUN apk add --no-cache python3 make g++ gcc musl-dev

WORKDIR /app

# Copy root package files
COPY package.json package-lock.json ./

# ── Stage 2: Root Dependencies ───────────────
FROM base AS root-deps

# Install root dependencies
RUN npm ci --omit=dev

# ── Stage 3: Bridge Dependencies ─────────────
FROM base AS bridge-deps

WORKDIR /app/ghostnet-bridge
COPY ghostnet-bridge/package.json ghostnet-bridge/package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

# ── Stage 4: Client Dependencies ─────────────
FROM base AS client-deps

WORKDIR /app/ghostnet-client
COPY ghostnet-client/package.json ghostnet-client/package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

# ── Stage 5: Relay Dependencies ──────────────
FROM base AS relay-deps

WORKDIR /app/ghostnet-bridge/relay
COPY ghostnet-bridge/relay/package.json ghostnet-bridge/relay/package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

# ── Stage 6: Production Image ────────────────
FROM node:20-alpine AS production

# Add tini for proper PID 1 signal handling
RUN apk add --no-cache tini curl

WORKDIR /app

# Copy root node_modules
COPY --from=root-deps /app/node_modules ./node_modules

# Copy ALL application source code
COPY . .

# Remove any existing node_modules from subdirectories (we'll overlay)
RUN rm -rf ghostnet-bridge/node_modules ghostnet-client/node_modules ghostnet-bridge/relay/node_modules

# Copy sub-project node_modules from build stages
COPY --from=bridge-deps /app/ghostnet-bridge/node_modules ./ghostnet-bridge/node_modules
COPY --from=client-deps /app/ghostnet-client/node_modules ./ghostnet-client/node_modules
COPY --from=relay-deps /app/ghostnet-bridge/relay/node_modules ./ghostnet-bridge/relay/node_modules

# Remove files that should NOT be in the image
RUN rm -rf .git .env .env.* *.sqlite logs/* node_modules/.cache

# Create data directories
RUN mkdir -p /app/logs /app/data

# Create a non-root user for security
RUN addgroup -S ghostnet && adduser -S ghostnet -G ghostnet
RUN chown -R ghostnet:ghostnet /app

USER ghostnet

# Default entrypoint with tini
ENTRYPOINT ["/sbin/tini", "--"]

# Default command — overridden per service in docker-compose
CMD ["node", "ghostnet-server.js"]
