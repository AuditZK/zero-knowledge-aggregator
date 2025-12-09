#!/bin/bash
# =============================================================================
# Simple Production Deployment Script (NO Kubernetes required)
# =============================================================================
# Deploys the enclave on a single AMD SEV-SNP VM using Docker Compose + systemd
#
# Requirements:
# - Ubuntu 22.04 LTS with AMD SEV-SNP support
# - Docker and Docker Compose installed
#
# Usage:
#   ./deploy-simple.sh
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
INSTALL_DIR="/opt/track-record-enclave"
ENV_FILE="/etc/enclave/.env.production"
SYSTEMD_SERVICE="/etc/systemd/system/enclave.service"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Track Record Enclave - Simple Deployment${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running on AMD SEV-SNP VM
if [ ! -e /dev/sev-guest ] && [ "$AMD_SEV_SNP" != "false" ]; then
  echo -e "${YELLOW}⚠ WARNING: /dev/sev-guest not found${NC}"
  echo -e "${YELLOW}⚠ This doesn't appear to be an AMD SEV-SNP VM${NC}"
  echo ""
  read -p "Continue anyway? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

# 1. Install dependencies
echo -e "${GREEN}[1/7] Installing dependencies...${NC}"
if ! command -v docker &> /dev/null; then
  echo "Installing Docker..."
  curl -fsSL https://get.docker.com -o get-docker.sh
  sudo sh get-docker.sh
  sudo usermod -aG docker $USER
  rm get-docker.sh
else
  echo "Docker already installed"
fi

if ! command -v docker-compose &> /dev/null; then
  echo "Installing Docker Compose..."
  sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
else
  echo "Docker Compose already installed"
fi

# 2. Create installation directory
echo -e "${GREEN}[2/7] Creating installation directory...${NC}"
sudo mkdir -p "$INSTALL_DIR"
sudo mkdir -p /etc/enclave/certs
sudo mkdir -p /var/log/enclave

# 3. Copy application files
echo -e "${GREEN}[3/7] Copying application files...${NC}"
sudo cp -r . "$INSTALL_DIR/"
sudo chown -R root:root "$INSTALL_DIR"

# 4. Setup environment variables
echo -e "${GREEN}[4/7] Setting up environment variables...${NC}"

if [ ! -f "$ENV_FILE" ]; then
  echo -e "${YELLOW}⚠ Creating production environment file...${NC}"

  # Create .env.production from template
  sudo cp "$INSTALL_DIR/.env.production.example" "$ENV_FILE"

  sudo chmod 600 "$ENV_FILE"
  echo -e "${GREEN}✓ Environment file created at $ENV_FILE${NC}"
  echo -e "${YELLOW}⚠ IMPORTANT: Edit $ENV_FILE and set DATABASE_URL, JWT_SECRET${NC}"
else
  echo "Environment file already exists at $ENV_FILE"
fi

# 5. Setup TLS certificates
echo -e "${GREEN}[5/7] Setting up TLS certificates...${NC}"

if [ ! -f /etc/enclave/certs/server.crt ]; then
  echo -e "${YELLOW}⚠ No TLS certificates found${NC}"
  echo "Generating self-signed certificates (REPLACE with CA-signed in production)..."

  # Generate self-signed certs (temporary)
  sudo openssl req -x509 -newkey rsa:4096 \
    -keyout /etc/enclave/certs/ca.key \
    -out /etc/enclave/certs/ca.crt \
    -days 3650 -nodes \
    -subj "/CN=Track Record Enclave CA/O=Track Record/C=US" 2>/dev/null

  sudo openssl genrsa -out /etc/enclave/certs/server.key 4096 2>/dev/null

  sudo openssl req -new \
    -key /etc/enclave/certs/server.key \
    -out /etc/enclave/certs/server.csr \
    -subj "/CN=enclave.trackrecord.internal/O=Track Record/C=US" 2>/dev/null

  sudo openssl x509 -req \
    -in /etc/enclave/certs/server.csr \
    -CA /etc/enclave/certs/ca.crt \
    -CAkey /etc/enclave/certs/ca.key \
    -CAcreateserial \
    -out /etc/enclave/certs/server.crt \
    -days 365 -sha256 2>/dev/null

  sudo rm /etc/enclave/certs/server.csr

  sudo chmod 600 /etc/enclave/certs/*.key
  sudo chmod 644 /etc/enclave/certs/*.crt

  echo -e "${GREEN}✓ Self-signed certificates generated${NC}"
  echo -e "${YELLOW}⚠ Replace with CA-signed certificates for production${NC}"
else
  echo "TLS certificates already exist"
fi

# 6. Build Docker image
echo -e "${GREEN}[6/7] Building Docker image...${NC}"
cd "$INSTALL_DIR"
sudo docker build -f Dockerfile.reproducible -t track-record-enclave:latest .

# Calculate build hash for verification
echo -e "${BLUE}Calculating build hash...${NC}"
BUILD_HASH=$(sudo docker run --rm track-record-enclave:latest cat BUILD_HASH.txt)
echo -e "${GREEN}Build hash: $BUILD_HASH${NC}"

# 7. Setup systemd service
echo -e "${GREEN}[7/7] Setting up systemd service...${NC}"

sudo cp "$INSTALL_DIR/deployment/systemd/enclave.service" "$SYSTEMD_SERVICE"
sudo systemctl daemon-reload
sudo systemctl enable enclave.service

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Deployment completed successfully${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}NEXT STEPS:${NC}"
echo ""
echo "1. Review configuration:"
echo "   ${BLUE}sudo nano $ENV_FILE${NC}"
echo ""
echo "2. Update DATABASE_URL with your PostgreSQL connection string"
echo ""
echo "3. Start the enclave:"
echo "   ${BLUE}sudo systemctl start enclave${NC}"
echo ""
echo "4. Check status:"
echo "   ${BLUE}sudo systemctl status enclave${NC}"
echo ""
echo "5. View logs:"
echo "   ${BLUE}sudo journalctl -u enclave -f${NC}"
echo ""
echo "6. Verify health:"
echo "   ${BLUE}curl http://localhost:9090/health${NC}"
echo ""
echo "7. Check metrics:"
echo "   ${BLUE}curl http://localhost:9090/metrics${NC}"
echo ""
echo -e "${RED}⚠ SECURITY REMINDERS:${NC}"
echo "  - Replace self-signed certs with CA-signed certificates"
echo "  - Verify AMD SEV-SNP hardware is available (encryption keys derived from hardware)"
echo "  - Configure firewall to restrict port 50051 to internal network only"
echo "  - Enable automatic security updates: sudo apt install unattended-upgrades"
echo ""
