#!/bin/bash
# ============================================================================
# Track Record Enclave - Build Measurement Script
# ============================================================================
# This script builds the enclave image and calculates its measurement hash.
# The measurement is used to verify attestation reports.
#
# Usage:
#   ./scripts/build-measurement.sh [--push]
#
# Output:
#   - Docker image: track-record-enclave:latest
#   - Measurement file: measurements/measurement-<version>-<date>.txt
#   - SHA-384 hash for attestation verification
# ============================================================================

set -e

# Configuration
IMAGE_NAME="track-record-enclave"
VERSION=$(node -p "require('./package.json').version")
DATE=$(date +%Y%m%d)
MEASUREMENTS_DIR="measurements"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} Track Record Enclave - Build Measurement${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Version: ${VERSION}"
echo "Date: ${DATE}"
echo ""

# Create measurements directory
mkdir -p ${MEASUREMENTS_DIR}

# Step 1: Build Docker image with reproducible settings
echo -e "${YELLOW}Step 1: Building Docker image...${NC}"
docker build \
    --no-cache \
    --platform linux/amd64 \
    -t ${IMAGE_NAME}:${VERSION} \
    -t ${IMAGE_NAME}:latest \
    .

echo -e "${GREEN}Docker image built successfully${NC}"
echo ""

# Step 2: Export image to tarball
echo -e "${YELLOW}Step 2: Exporting image to tarball...${NC}"
TARBALL="${MEASUREMENTS_DIR}/${IMAGE_NAME}-${VERSION}.tar"
docker save ${IMAGE_NAME}:${VERSION} > "${TARBALL}"
echo "Tarball: ${TARBALL}"
echo ""

# Step 3: Calculate SHA-384 hash (same as SEV-SNP measurement)
echo -e "${YELLOW}Step 3: Calculating SHA-384 measurement...${NC}"
if command -v sha384sum &> /dev/null; then
    MEASUREMENT=$(sha384sum "${TARBALL}" | cut -d' ' -f1)
elif command -v shasum &> /dev/null; then
    MEASUREMENT=$(shasum -a 384 "${TARBALL}" | cut -d' ' -f1)
else
    echo -e "${RED}Error: sha384sum or shasum not found${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} MEASUREMENT HASH (SHA-384)${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${YELLOW}${MEASUREMENT}${NC}"
echo ""

# Step 4: Save measurement to file
MEASUREMENT_FILE="${MEASUREMENTS_DIR}/measurement-${VERSION}-${DATE}.txt"
cat > "${MEASUREMENT_FILE}" << EOF
Track Record Enclave - Build Measurement
=========================================

Version: ${VERSION}
Build Date: ${DATE}
Build Time: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

Docker Image: ${IMAGE_NAME}:${VERSION}
Platform: linux/amd64
Base Image: node:20.18.1-alpine3.21

MEASUREMENT (SHA-384):
${MEASUREMENT}

Verification Instructions:
1. Build the same image from source:
   docker build --platform linux/amd64 -t ${IMAGE_NAME}:verify .

2. Export and hash:
   docker save ${IMAGE_NAME}:verify | sha384sum

3. Compare with measurement above

4. In attestation report, verify measurement field matches

For SEV-SNP attestation:
- The 'measurement' field in GetAttestationReport response
  should match this hash when running in production enclave.
- Verify AMD signature on attestation report using AMD root certificate.

Git Commit: $(git rev-parse HEAD 2>/dev/null || echo "N/A")
EOF

echo "Measurement saved to: ${MEASUREMENT_FILE}"
echo ""

# Step 5: Calculate code hash (source code integrity)
echo -e "${YELLOW}Step 4: Calculating source code hash...${NC}"
CODE_HASH=$(find src -name "*.ts" -type f -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)
echo "Source Code Hash (SHA-256): ${CODE_HASH}"
echo ""
echo "Code Hash: ${CODE_HASH}" >> "${MEASUREMENT_FILE}"

# Step 6: Display verification command
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} Verification Command${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "To verify this build locally:"
echo "  docker save ${IMAGE_NAME}:${VERSION} | sha384sum"
echo ""
echo "Expected output:"
echo "  ${MEASUREMENT}  -"
echo ""

# Clean up tarball (optional)
if [ "$1" != "--keep-tarball" ]; then
    rm -f "${TARBALL}"
    echo "Tarball removed (use --keep-tarball to preserve)"
fi

# Push to registry if requested
if [ "$1" == "--push" ]; then
    echo -e "${YELLOW}Pushing to registry...${NC}"
    docker push ${IMAGE_NAME}:${VERSION}
    docker push ${IMAGE_NAME}:latest
    echo -e "${GREEN}Pushed successfully${NC}"
fi

echo ""
echo -e "${GREEN}Build measurement complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Commit measurement file to repository"
echo "2. Publish measurement in GitHub releases"
echo "3. Users can verify by comparing attestation report measurement"
