#!/bin/bash

# Deploy script for zero-knowledge-aggregator enclave on VPS
# Run this script ON THE VPS (not locally)

set -e  # Exit on error

echo "🚀 Deploying zero-knowledge-aggregator to VPS..."
echo ""

# Configuration
PROJECT_DIR="/root/zero-knowledge-aggregator"
BRANCH="feature/integrate-performance-metrics"

# Step 1: Navigate to project directory
echo "📁 Navigating to project directory..."
cd "$PROJECT_DIR"

# Step 2: Fetch latest changes
echo "🔄 Fetching latest changes from GitHub..."
git fetch origin

# Step 3: Checkout feature branch
echo "🌿 Switching to branch: $BRANCH"
git checkout "$BRANCH"

# Step 4: Pull latest changes
echo "⬇️  Pulling latest changes..."
git pull origin "$BRANCH"

# Step 5: Show current commit
echo ""
echo "📌 Current commit:"
git log -1 --oneline
echo ""

# Step 6: Install dependencies
echo "📦 Installing dependencies..."
npm install --production=false

# Step 7: Generate Prisma client
echo "🔧 Generating Prisma client..."
npx prisma generate

# Step 8: Build TypeScript
echo "🏗️  Building TypeScript..."
npm run build

# Step 9: Rebuild Docker image and restart container
echo "🐳 Rebuilding Docker image..."
docker build -t enclave:latest -f Dockerfile .

echo "🐳 Stopping and removing old container..."
docker stop enclave || true
docker rm enclave || true

echo "🐳 Starting new container with updated image..."
docker run -d \
  --name enclave \
  -p 50051:50051 \
  -p 3050:3050 \
  --env-file .env \
  enclave:latest

echo "✅ Enclave container rebuilt and restarted"

# Step 10: Show logs
echo ""
echo "📋 Enclave logs (last 50 lines):"
docker logs --tail=50 enclave

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📊 To view live logs:"
echo "   docker logs -f enclave"
echo ""
echo "🔍 To check health:"
echo "   node test-performance-metrics.js"
echo ""
