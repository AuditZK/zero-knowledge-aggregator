#!/bin/bash
# ==============================================================================
# Setup GCP Secret Manager for Enclave
# ==============================================================================
# Run this script ONCE to create secrets in GCP Secret Manager
# Requires: gcloud CLI with appropriate permissions
# ==============================================================================

set -e

PROJECT_ID=$(gcloud config get-value project)
VM_NAME="tee-milan-01"
ZONE="us-central1-a"

echo "=== GCP Secret Manager Setup for Enclave ==="
echo "Project: $PROJECT_ID"
echo ""

# Get VM service account
SERVICE_ACCOUNT=$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(serviceAccounts[0].email)')
echo "VM Service Account: $SERVICE_ACCOUNT"
echo ""

# Create DATABASE_URL secret
echo "Creating enclave-database-url secret..."
if gcloud secrets describe enclave-database-url &>/dev/null; then
    echo "  Secret already exists, updating..."
    echo -n "Enter Neon DATABASE_URL: "
    read -s DATABASE_URL
    echo ""
    echo -n "$DATABASE_URL" | gcloud secrets versions add enclave-database-url --data-file=-
else
    echo -n "Enter Neon DATABASE_URL: "
    read -s DATABASE_URL
    echo ""
    echo -n "$DATABASE_URL" | gcloud secrets create enclave-database-url --data-file=-
fi
echo "  Done!"

# Create JWT_SECRET secret
echo "Creating enclave-jwt-secret secret..."
JWT_SECRET=$(openssl rand -hex 32)
if gcloud secrets describe enclave-jwt-secret &>/dev/null; then
    echo "  Secret already exists, creating new version..."
    echo -n "$JWT_SECRET" | gcloud secrets versions add enclave-jwt-secret --data-file=-
else
    echo -n "$JWT_SECRET" | gcloud secrets create enclave-jwt-secret --data-file=-
fi
echo "  Done!"

# Grant access to VM service account
echo ""
echo "Granting access to VM service account..."

gcloud secrets add-iam-policy-binding enclave-database-url \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet

gcloud secrets add-iam-policy-binding enclave-jwt-secret \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet

echo "  Done!"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Secrets created:"
echo "  - enclave-database-url"
echo "  - enclave-jwt-secret"
echo ""
echo "Next steps on the VM ($VM_NAME):"
echo "  1. Copy the systemd service:"
echo "     sudo cp deployment/enclave.service /etc/systemd/system/"
echo "     sudo systemctl daemon-reload"
echo "     sudo systemctl enable enclave"
echo ""
echo "  2. Start the service:"
echo "     sudo systemctl start enclave"
echo ""
echo "  3. Check status:"
echo "     sudo systemctl status enclave"
echo "     docker logs enclave_service"
