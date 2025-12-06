# ============================================================================
# Track Record Enclave - Docker Image (Production SEV-SNP)
# ============================================================================
# This Dockerfile builds the enclave with AMD SEV-SNP attestation support
# Requires deployment on a Confidential VM with SEV-SNP hardware
# ============================================================================

# ============================================================================
# SNPGuest Builder Stage - Build AMD SEV-SNP attestation tool
# ============================================================================
FROM rust:1.75-alpine AS snpguest-builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

# Install snpguest 0.6.0 (compatible with rust 1.75)
RUN cargo install snpguest@0.6.0 --root /usr/local

# ============================================================================
# Node Builder Stage
# ============================================================================
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    openssl

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install ALL dependencies (including devDependencies for build)
RUN npm ci && \
    npm cache clean --force

# Copy source code
COPY src ./src
COPY prisma ./prisma

# Generate Prisma Client
RUN npx prisma generate

# Build TypeScript
RUN npm run build

# ============================================================================
# Production Stage
# ============================================================================
FROM node:20-alpine

# Install runtime dependencies
RUN apk add --no-cache \
    openssl \
    ca-certificates \
    tini

# Copy snpguest binary for SEV-SNP attestation
COPY --from=snpguest-builder /usr/local/bin/snpguest /usr/bin/snpguest

# Create non-root user for security
RUN addgroup -g 1001 enclave && \
    adduser -D -u 1001 -G enclave enclave

WORKDIR /app

# Copy package files and install production dependencies only
COPY --chown=enclave:enclave package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy built application from builder
COPY --from=builder --chown=enclave:enclave /app/dist ./dist

# Copy proto files to dist/proto (required at runtime)
COPY --chown=enclave:enclave src/proto ./dist/proto

# Copy Prisma schema and generated client
COPY --from=builder --chown=enclave:enclave /app/prisma ./prisma
COPY --from=builder --chown=enclave:enclave /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder --chown=enclave:enclave /app/node_modules/@prisma ./node_modules/@prisma

# Environment variables (defaults - override in docker-compose.yml)
ENV NODE_ENV=production
ENV ENCLAVE_PORT=50051
ENV HTTP_LOG_PORT=50052
ENV METRICS_PORT=9090
ENV METRICS_ENABLED=true

# Health check - use PORT if set (Cloud Run), otherwise HTTP_LOG_PORT or 50052
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD node -e "const port = process.env.PORT || process.env.HTTP_LOG_PORT || '50052'; require('http').get('http://localhost:' + port + '/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Expose ports
EXPOSE 50051 50052 9090

# Switch to non-root user
USER enclave

# Use tini as init system (proper signal handling)
ENTRYPOINT ["/sbin/tini", "--"]

# Start the enclave application
CMD ["node", "dist/index.js"]
