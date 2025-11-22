# Reproducible Build Instructions

This document explains how to build the Track Record Enclave from source and verify the build is reproducible.

## 🎯 Why Reproducible Builds?

Reproducible builds ensure that:
1. The binary running in production matches the published source code
2. No hidden backdoors or malicious code was inserted during build
3. Independent auditors can verify the build
4. Users can trust the enclave with their credentials

## 📋 Prerequisites

- **Node.js**: v20.x (exact version matters for reproducibility)
- **npm**: v10.x
- **Operating System**: Linux (Ubuntu 22.04 LTS recommended)
- **Git**: v2.x

## 🔧 Build Steps

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/track-record-enclave.git
cd track-record-enclave

# Checkout specific tag for production
git checkout v1.0.0
```

### 2. Verify Git Commit Hash

```bash
# Get current commit hash
git rev-parse HEAD

# Should match published hash:
# Expected: <COMMIT_HASH_HERE>
```

### 3. Install Exact Dependencies

```bash
# Install exact versions from package-lock.json
npm ci

# DO NOT use 'npm install' as it may update dependencies
```

### 4. Generate Prisma Client

```bash
npm run prisma:generate
```

### 5. Build TypeScript

```bash
# Build with consistent settings
npm run build

# This runs: tsc
# Using tsconfig.json settings
```

### 6. Calculate Build Hash

```bash
# Generate SHA-256 hash of all built files
find dist -type f -name "*.js" -exec sha256sum {} \; | sort -k 2 | sha256sum

# Expected hash for v1.0.0:
# <BUILD_HASH_HERE>
```

## 🔍 Verification Process

### Verify Source Code Integrity

```bash
# 1. Verify git tag signature (if signed)
git tag -v v1.0.0

# 2. Verify commit hash
git rev-parse HEAD
# Should match: <COMMIT_HASH>
```

### Verify Build Output

```bash
# 1. Build the project
npm ci
npm run build

# 2. Calculate hash of dist/ directory
tar -cf - dist/ | sha256sum

# 3. Compare with published hash
# Published hash: <DIST_HASH>
```

### Verify Dependencies

```bash
# Check for known vulnerabilities
npm audit

# Verify package-lock.json integrity
npm ci --dry-run
```

## 📦 Docker Build (Recommended)

For maximum reproducibility, use Docker with fixed base image:

```bash
# Build using Dockerfile.reproducible
docker build -f Dockerfile.reproducible -t track-record-enclave:v1.0.0 .

# Extract built files
docker create --name enclave-build track-record-enclave:v1.0.0
docker cp enclave-build:/app/dist ./dist-verify
docker rm enclave-build

# Verify hash
tar -cf - dist-verify/ | sha256sum
```

## 🏗️ Build Environment

For bit-for-bit reproducibility, use the exact build environment:

### Docker Image

```dockerfile
FROM node:20.11.0-alpine3.19

# Install build dependencies
RUN apk add --no-cache \
    git \
    python3 \
    make \
    g++

WORKDIR /app

# Copy source
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Build
RUN npm run build

# Verify
RUN find dist -type f -name "*.js" -exec sha256sum {} \; | sort -k 2 | sha256sum
```

### Environment Variables

None required for build (only for runtime).

## 📊 Build Metrics

| Metric | Value |
|--------|-------|
| **Source LOC** | 4,572 |
| **Built JS Files** | ~80 |
| **Total Build Size** | ~15 MB |
| **Build Time** | ~30 seconds |
| **Dependencies** | 47 packages |

## 🔐 Security Considerations

### What to Verify

1. ✅ Git commit hash matches published version
2. ✅ No modifications to source files
3. ✅ Dependencies match package-lock.json
4. ✅ Build output hash matches published hash
5. ✅ No vulnerabilities in npm audit

### Red Flags

- ❌ Uncommitted changes in git
- ❌ Different package versions than package-lock.json
- ❌ Build hash doesn't match
- ❌ High/critical vulnerabilities in dependencies

## 📝 Publishing Build Artifacts

When releasing a new version:

```bash
# 1. Tag the release
git tag -s v1.0.0 -m "Release v1.0.0"

# 2. Build
npm ci
npm run build

# 3. Calculate and publish hashes
find dist -type f -name "*.js" -exec sha256sum {} \; | sort -k 2 > dist/SHA256SUMS
sha256sum dist/SHA256SUMS

# 4. Push tag
git push origin v1.0.0

# 5. Create GitHub release with:
#    - Source tarball
#    - Built dist/ directory (optional)
#    - SHA256SUMS file
#    - Build instructions
```

## 🧪 Automated Verification

### GitHub Actions

See `.github/workflows/verify-build.yml` for automated verification on every commit.

### Local Verification Script

```bash
# Run verification script
./scripts/verify-build.sh v1.0.0

# Should output:
# ✅ Source code verified
# ✅ Dependencies verified
# ✅ Build hash verified
# ✅ Build is reproducible!
```

## 📞 Questions?

If you encounter issues with reproducible builds:

1. Check you're using the exact Node.js version (20.11.0)
2. Ensure you're on a clean Linux environment
3. Verify no local modifications to source
4. Open an issue on GitHub

## 🔗 Related Documents

- [SECURITY.md](SECURITY.md) - Security policy
- [ATTESTATION.md](ATTESTATION.md) - SEV-SNP attestation verification
- [README.md](README.md) - General documentation