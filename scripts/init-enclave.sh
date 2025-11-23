#!/bin/bash

#############################################################################
# Track Record Enclave - Initialization Script
#
# This script securely initializes the enclave environment by:
# 1. Generating strong cryptographic keys
# 2. Creating TLS certificates
# 3. Setting up environment configuration
# 4. Securing file permissions
#
# Usage:
#   ./scripts/init-enclave.sh [--production|--development]
#
# SECURITY:
# - ENCRYPTION_KEY: 256-bit random key (64 hex chars)
# - TLS certificates: 4096-bit RSA (production) or self-signed (development)
# - Permissions: Keys readable only by enclave process
#############################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Determine environment
ENVIRONMENT="${1:-development}"
if [[ "$ENVIRONMENT" != "production" && "$ENVIRONMENT" != "development" ]]; then
  echo -e "${RED}Error: Invalid environment. Use --production or --development${NC}"
  exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Track Record Enclave - Initialization${NC}"
echo -e "${BLUE}Environment: ${ENVIRONMENT}${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check for required commands
for cmd in openssl node; do
  if ! command -v $cmd &> /dev/null; then
    echo -e "${RED}Error: $cmd is not installed${NC}"
    exit 1
  fi
done

#############################################################################
# 1. Generate ENCRYPTION_KEY
#############################################################################

echo -e "${GREEN}[1/4] Generating encryption key...${NC}"

if [ -f .env ]; then
  # Check if ENCRYPTION_KEY already exists and is not the example key
  EXISTING_KEY=$(grep -E '^ENCRYPTION_KEY=' .env | cut -d '=' -f 2- | tr -d '"' || echo "")
  EXAMPLE_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

  if [ -n "$EXISTING_KEY" ] && [ "$EXISTING_KEY" != "$EXAMPLE_KEY" ]; then
    echo -e "${YELLOW}  ⚠ ENCRYPTION_KEY already exists in .env${NC}"
    echo -e "${YELLOW}  ⚠ Changing this key will make existing encrypted data unrecoverable${NC}"
    read -p "  Do you want to regenerate it? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo -e "${BLUE}  → Keeping existing ENCRYPTION_KEY${NC}"
      ENCRYPTION_KEY="$EXISTING_KEY"
    else
      # Generate new key
      ENCRYPTION_KEY=$(openssl rand -hex 32)
      echo -e "${GREEN}  ✓ Generated new ENCRYPTION_KEY (old data will be unrecoverable)${NC}"
    fi
  else
    # Generate new key (example key detected or no key)
    ENCRYPTION_KEY=$(openssl rand -hex 32)
    echo -e "${GREEN}  ✓ Generated new ENCRYPTION_KEY: ${ENCRYPTION_KEY:0:16}...${NC}"
  fi
else
  # No .env file, generate key
  ENCRYPTION_KEY=$(openssl rand -hex 32)
  echo -e "${GREEN}  ✓ Generated ENCRYPTION_KEY: ${ENCRYPTION_KEY:0:16}...${NC}"
fi

#############################################################################
# 2. Generate JWT Secret
#############################################################################

echo -e "${GREEN}[2/4] Generating JWT secret...${NC}"

JWT_SECRET=$(openssl rand -hex 32)
echo -e "${GREEN}  ✓ Generated JWT_SECRET${NC}"

#############################################################################
# 3. Generate TLS Certificates
#############################################################################

echo -e "${GREEN}[3/4] Generating TLS certificates...${NC}"

TLS_DIR="/etc/enclave"
if [ "$ENVIRONMENT" = "development" ]; then
  TLS_DIR="./certs"
fi

mkdir -p "$TLS_DIR"

if [ "$ENVIRONMENT" = "production" ]; then
  echo -e "${YELLOW}  ⚠ PRODUCTION mode${NC}"
  echo -e "${YELLOW}  ⚠ You should use certificates from a trusted CA${NC}"
  echo -e "${YELLOW}  ⚠ Self-signed certificates are NOT recommended for production${NC}"
  echo ""
  read -p "  Generate self-signed certificates anyway? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}  → Skipping certificate generation${NC}"
    echo -e "${BLUE}  → Place your CA-signed certificates in ${TLS_DIR}:${NC}"
    echo -e "${BLUE}     - ca.crt (CA certificate)${NC}"
    echo -e "${BLUE}     - server.crt (Server certificate)${NC}"
    echo -e "${BLUE}     - server.key (Server private key)${NC}"
    SKIP_TLS=true
  fi
fi

if [ "${SKIP_TLS:-false}" != "true" ]; then
  # Generate CA certificate (self-signed root)
  if [ ! -f "$TLS_DIR/ca.crt" ]; then
    openssl req -x509 -newkey rsa:4096 \
      -keyout "$TLS_DIR/ca.key" \
      -out "$TLS_DIR/ca.crt" \
      -days 3650 \
      -nodes \
      -subj "/CN=Track Record Enclave CA/O=Track Record/C=US" \
      2>/dev/null
    echo -e "${GREEN}  ✓ Generated CA certificate (${TLS_DIR}/ca.crt)${NC}"
  else
    echo -e "${BLUE}  → CA certificate already exists${NC}"
  fi

  # Generate server certificate signed by CA
  if [ ! -f "$TLS_DIR/server.crt" ]; then
    # Generate server private key
    openssl genrsa -out "$TLS_DIR/server.key" 4096 2>/dev/null

    # Generate CSR (Certificate Signing Request)
    openssl req -new \
      -key "$TLS_DIR/server.key" \
      -out "$TLS_DIR/server.csr" \
      -subj "/CN=enclave.trackrecord.local/O=Track Record/C=US" \
      2>/dev/null

    # Sign CSR with CA to create server certificate
    openssl x509 -req \
      -in "$TLS_DIR/server.csr" \
      -CA "$TLS_DIR/ca.crt" \
      -CAkey "$TLS_DIR/ca.key" \
      -CAcreateserial \
      -out "$TLS_DIR/server.crt" \
      -days 365 \
      -sha256 \
      2>/dev/null

    # Clean up CSR
    rm "$TLS_DIR/server.csr"

    echo -e "${GREEN}  ✓ Generated server certificate (${TLS_DIR}/server.crt)${NC}"
  else
    echo -e "${BLUE}  → Server certificate already exists${NC}"
  fi

  # Set strict permissions (readable only by owner)
  chmod 600 "$TLS_DIR"/*.key 2>/dev/null || true
  chmod 644 "$TLS_DIR"/*.crt 2>/dev/null || true

  echo -e "${GREEN}  ✓ TLS certificates ready in ${TLS_DIR}${NC}"
fi

#############################################################################
# 4. Create .env file
#############################################################################

echo -e "${GREEN}[4/4] Creating .env configuration...${NC}"

# Backup existing .env if it exists
if [ -f .env ]; then
  cp .env .env.backup.$(date +%Y%m%d_%H%M%S)
  echo -e "${YELLOW}  ⚠ Backed up existing .env${NC}"
fi

# Create .env from template
cat > .env << EOF
# =============================================================================
# TRACK RECORD ENCLAVE - ENVIRONMENT CONFIGURATION
# =============================================================================
# Generated: $(date)
# Environment: ${ENVIRONMENT}
# =============================================================================

# -----------------------------------------------------------------------------
# ENCLAVE CONFIGURATION
# -----------------------------------------------------------------------------
ENCLAVE_MODE=true
AMD_SEV_SNP=false
ENCLAVE_PORT=50051

# -----------------------------------------------------------------------------
# DATABASE (Enclave User - Full Access)
# -----------------------------------------------------------------------------
DATABASE_URL="postgresql://enclave_user:enclavepass123@localhost:5434/aggregator_db"
POSTGRES_PASSWORD="enclavepass123"

# -----------------------------------------------------------------------------
# SECURITY (CRITICAL - AUTO-GENERATED)
# -----------------------------------------------------------------------------
# 🔒 NEVER commit this file to Git
# 🔒 Changing ENCRYPTION_KEY will make existing encrypted data unrecoverable
ENCRYPTION_KEY="${ENCRYPTION_KEY}"
JWT_SECRET="${JWT_SECRET}"

# -----------------------------------------------------------------------------
# LOGGING
# -----------------------------------------------------------------------------
LOG_LEVEL="info"
QUERY_LOGGING="false"

# -----------------------------------------------------------------------------
# TLS CERTIFICATES
# -----------------------------------------------------------------------------
TLS_CA_CERT="${TLS_DIR}/ca.crt"
TLS_SERVER_CERT="${TLS_DIR}/server.crt"
TLS_SERVER_KEY="${TLS_DIR}/server.key"

# -----------------------------------------------------------------------------
# NODE ENVIRONMENT
# -----------------------------------------------------------------------------
NODE_ENV="${ENVIRONMENT}"
EOF

echo -e "${GREEN}  ✓ Created .env file${NC}"

# Set .env permissions (owner read/write only)
chmod 600 .env

#############################################################################
# Summary
#############################################################################

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Enclave initialized successfully${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}SECURITY CHECKLIST:${NC}"
echo -e "  [$([ -f .env ] && echo '✓' || echo '✗')] .env file created"
echo -e "  [$([ -n "${ENCRYPTION_KEY}" ] && [ "${ENCRYPTION_KEY}" != "${EXAMPLE_KEY:-}" ] && echo '✓' || echo '✗')] Strong ENCRYPTION_KEY generated"
echo -e "  [$([ -f "${TLS_DIR}/ca.crt" ] && echo '✓' || echo '✗')] TLS certificates present"
echo -e "  [$([ $(stat -c %a .env 2>/dev/null || stat -f %A .env 2>/dev/null) = "600" ] && echo '✓' || echo '?')] .env permissions secured"
echo ""
echo -e "${YELLOW}NEXT STEPS:${NC}"
echo -e "  1. Review .env configuration"
echo -e "  2. Start database: ${BLUE}npm run docker:up${NC}"
echo -e "  3. Initialize Prisma: ${BLUE}npm run prisma:generate${NC}"
echo -e "  4. Start enclave: ${BLUE}npm run dev${NC}"
echo ""
echo -e "${RED}⚠ IMPORTANT:${NC}"
echo -e "  - NEVER commit .env to Git"
echo -e "  - Store ENCRYPTION_KEY securely (password manager, vault)"
echo -e "  - For production, use CA-signed TLS certificates"
echo -e "  - Deploy to AMD SEV-SNP hardware for true isolation"
echo ""
