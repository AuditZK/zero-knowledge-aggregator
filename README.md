# Track Record Platform - Enclave Worker 🔒

**Open Source Auditable Code for AMD SEV-SNP Confidential Computing**

This repository contains the **Trusted Computing Base (TCB)** for the Track Record Platform's trading data aggregation service. It runs inside an AMD SEV-SNP hardware-isolated enclave.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![TCB Size](https://img.shields.io/badge/TCB-4,572%20LOC-blue.svg)]()

## 🎯 What is this?

This service runs in an **AMD SEV-SNP encrypted VM** and handles:
- ✅ Decrypting user API credentials (exchanges)
- ✅ Fetching individual trades from exchanges (Binance, IBKR, Alpaca, etc.)
- ✅ Aggregating trades into hourly returns
- ❌ **Never** exposing individual trades outside the enclave

## 🔐 Why Open Source?

**Transparency and Auditability**: Users need to verify that:
1. Their credentials are never logged or leaked
2. Individual trades stay inside the enclave
3. Only aggregated, anonymized data leaves the enclave
4. The code matches the binary running in production (reproducible builds)

## 📊 Trusted Computing Base (TCB)

| Component | LOC | Purpose |
|-----------|-----|---------|
| **EncryptionService** | 200 | AES-256-GCM credential decryption |
| **Exchange Connectors** | 1,400 | CCXT, IBKR, Alpaca integrations |
| **External API Services** | 1,441 | Trade fetching from exchanges |
| **EquitySnapshotAggregator** | 731 | Trade aggregation logic |
| **TradeSyncService** | 400 | Sync orchestration |
| **EnclaveRepository** | 300 | Database access layer |
| **EnclaveWorker + Server** | 100 | gRPC server and entry point |
| **TOTAL** | **4,572 LOC** | Minimized attack surface |

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│   API Gateway (Separate Service)   │
│   - HTTP REST API                   │
│   - NOT in this repo                │
└──────────────┬──────────────────────┘
               │ gRPC (Port 50051)
               ▼
╔══════════════════════════════════════╗
║   ENCLAVE WORKER (This Repo)         ║
║   AMD SEV-SNP Hardware Isolation     ║
╟──────────────────────────────────────╢
║  Input: gRPC sync requests           ║
║  Process:                            ║
║    1. Decrypt credentials            ║
║    2. Fetch trades from exchanges    ║
║    3. Aggregate into hourly returns  ║
║  Output: Aggregated data only        ║
╚══════════════════════════════════════╝
```

## 🚀 Quick Start

### Prerequisites
- Node.js 20+
- PostgreSQL 15+
- AMD SEV-SNP capable VM (production) or regular VM (development)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/track-record-enclave.git
cd track-record-enclave

# Install dependencies
npm install

# Generate Prisma client
npm run prisma:generate

# Build TypeScript
npm run build

# Configure environment
cp .env.example .env
# Edit .env with your credentials

# Start the enclave
npm start
```

## 🔧 Configuration

See [.env.example](.env.example) for all configuration options.

**Critical environment variables:**

```env
# Enclave mode
ENCLAVE_MODE=true
AMD_SEV_SNP=true  # Set to true in production

# Database (enclave has full access)
DATABASE_URL=postgresql://enclave_user:xxx@localhost:5433/aggregator_db

# Encryption key (32 bytes)
ENCRYPTION_KEY=your-32-byte-encryption-key

# gRPC port (internal only, not exposed to internet)
ENCLAVE_PORT=50051
```

## 📖 Documentation

- [BUILD.md](BUILD.md) - Reproducible build instructions
- [SECURITY.md](SECURITY.md) - Security policy and audit process
- [ATTESTATION.md](ATTESTATION.md) - How to verify SEV-SNP attestation
- [API.md](API.md) - gRPC API documentation

## 🔍 Security Guarantees

### What the Enclave CAN do:
- ✅ Decrypt user credentials (AES-256-GCM)
- ✅ Fetch trades from exchanges
- ✅ Read individual trades from database
- ✅ Calculate aggregated metrics

### What the Enclave CANNOT do:
- ❌ Accept HTTP requests (only gRPC from internal network)
- ❌ Send individual trades outside (only aggregated data)
- ❌ Log credentials or sensitive data
- ❌ Be accessed by the hypervisor (SEV-SNP protection)

## 🧪 Reproducible Builds

To verify the binary matches the source code:

```bash
# Build with reproducible flags
npm run build:reproducible

# Compare hash with published hash
sha256sum dist/**/*.js > build-hash.txt
```

See [BUILD.md](BUILD.md) for complete instructions.

## 📜 License

MIT License - See [LICENSE](LICENSE)

## 🤝 Contributing

We welcome security audits and contributions!

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

**Security vulnerabilities**: Please report privately to security@trackrecord.com

## 🏆 Audit Status

| Date | Auditor | Status | Report |
|------|---------|--------|--------|
| TBD | TBD | Pending | - |

## 📞 Contact

- Website: https://trackrecord.com
- Email: security@trackrecord.com
- GitHub Issues: https://github.com/your-org/track-record-enclave/issues

---

**Built with ❤️ for transparent, auditable confidential computing**