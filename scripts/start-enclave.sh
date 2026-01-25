#!/bin/bash
#############################################################################
# Start Enclave with GCP Metadata
#
# Reads secrets from GCP VM instance metadata and starts the enclave.
# This is the ONLY way to start the enclave in production - no .env files.
#
# Prerequisites:
#   1. GCP VM with metadata configured (see below)
#   2. Docker and docker-compose installed
#
# GCP Metadata keys required:
#   - database-url      (PostgreSQL connection string)
#   - encryption-key    (AES-256 key, 64 hex chars)
#   - jwt-secret        (JWT signing secret)
#   - benchmark-service-url (VPS benchmark API URL)
#
# Usage:
#   ./scripts/start-enclave.sh [--restart]
#############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

METADATA_URL="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
METADATA_HEADER="Metadata-Flavor: Google"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Track Record Enclave - Production Start${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if running on GCP
if ! curl -sf -H "$METADATA_HEADER" "$METADATA_URL/" > /dev/null 2>&1; then
  echo -e "${RED}ERROR: Not running on GCP or metadata server not accessible${NC}"
  echo -e "${RED}This script must be run on a GCP VM with metadata configured${NC}"
  exit 1
fi

echo -e "${GREEN}Loading secrets from GCP metadata...${NC}"

# Function to get metadata value
get_metadata() {
  local key="$1"
  local value
  value=$(curl -sf -H "$METADATA_HEADER" "$METADATA_URL/$key" 2>/dev/null) || echo ""
  echo "$value"
}

# Load required secrets from GCP metadata
export DATABASE_URL=$(get_metadata "database-url")
export ENCRYPTION_KEY=$(get_metadata "encryption-key")
export JWT_SECRET=$(get_metadata "jwt-secret")

# Load optional config from GCP metadata
export BENCHMARK_SERVICE_URL=$(get_metadata "benchmark-service-url")
export LOG_LEVEL=$(get_metadata "log-level")
export LOG_SERVER_API_KEY=$(get_metadata "log-server-api-key")
export SKIP_ATTESTATION=$(get_metadata "skip-attestation")
export GRAFANA_PASSWORD=$(get_metadata "grafana-password")
export ENCLAVE_DOMAIN=$(get_metadata "enclave-domain")

# Validate required secrets
MISSING=""
[[ -z "$DATABASE_URL" ]] && MISSING="$MISSING database-url"
[[ -z "$ENCRYPTION_KEY" ]] && MISSING="$MISSING encryption-key"
[[ -z "$JWT_SECRET" ]] && MISSING="$MISSING jwt-secret"

if [[ -n "$MISSING" ]]; then
  echo -e "${RED}ERROR: Missing required GCP metadata keys:${MISSING}${NC}"
  echo ""
  echo "Add them with:"
  echo "  gcloud compute instances add-metadata \$(hostname) \\"
  echo "    --zone=\$(curl -sH 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/zone | cut -d'/' -f4) \\"
  echo "    --metadata=database-url=postgresql://... \\"
  echo "    --metadata=encryption-key=... \\"
  echo "    --metadata=jwt-secret=..."
  exit 1
fi

echo -e "${GREEN}Loaded from GCP metadata:${NC}"
echo "  - DATABASE_URL: postgresql://...@[redacted]"
echo "  - ENCRYPTION_KEY: [redacted, ${#ENCRYPTION_KEY} chars]"
echo "  - JWT_SECRET: [redacted, ${#JWT_SECRET} chars]"
echo "  - BENCHMARK_SERVICE_URL: ${BENCHMARK_SERVICE_URL:-<not set>}"
echo "  - ENCLAVE_DOMAIN: ${ENCLAVE_DOMAIN:-<not set>}"
echo "  - LOG_LEVEL: ${LOG_LEVEL:-info}"
echo "  - SKIP_ATTESTATION: ${SKIP_ATTESTATION:-false}"
echo ""

# Handle restart flag
if [[ "${1:-}" == "--restart" ]]; then
  echo -e "${YELLOW}Restarting enclave...${NC}"
  cd "$PROJECT_DIR"
  docker compose -f docker-compose.enclave.yml down enclave-service
fi

# Start enclave
cd "$PROJECT_DIR"
echo -e "${GREEN}Starting enclave service...${NC}"
docker compose -f docker-compose.enclave.yml up -d enclave-service

echo ""
echo -e "${GREEN}Waiting for enclave to start...${NC}"
sleep 5

# Check status
if docker ps | grep -q enclave_service; then
  echo -e "${GREEN}========================================${NC}"
  echo -e "${GREEN}Enclave started successfully!${NC}"
  echo -e "${GREEN}========================================${NC}"
  echo ""
  docker ps | grep enclave_service
  echo ""
  echo "View logs: docker logs -f enclave_service"
else
  echo -e "${RED}ERROR: Enclave failed to start${NC}"
  echo "Check logs: docker logs enclave_service"
  exit 1
fi
