# Track Record Enclave Worker

**Trusted Computing Base for Confidential Trading Data Aggregation**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TCB](https://img.shields.io/badge/TCB-4,572%20LOC-green.svg)]()
[![Node.js](https://img.shields.io/badge/Node.js-20.x-339933.svg)]()
[![AMD SEV-SNP](https://img.shields.io/badge/AMD-SEV--SNP-red.svg)]()

## Overview

This repository contains the **Trusted Computing Base (TCB)** of the Track Record platform's data aggregation service. It implements a zero-knowledge architecture for processing sensitive trading data within an AMD SEV-SNP hardware-isolated enclave.

The service is designed to be independently auditable, with reproducible builds and minimal attack surface.

## Table of Contents

- [Security Model](#security-model)
- [Architecture](#architecture)
- [Trusted Computing Base](#trusted-computing-base)
- [Threat Model](#threat-model)
- [Build Instructions](#build-instructions)
- [Deployment](#deployment)
- [Audit Process](#audit-process)
- [API Specification](#api-specification)

## Security Model

### Trust Assumptions

1. **Hardware Root of Trust**: AMD SEV-SNP provides memory encryption and attestation
2. **Database Isolation**: PostgreSQL user `enclave_user` has exclusive access to sensitive tables
3. **Network Isolation**: Enclave is not exposed to public internet, only internal gRPC
4. **Cryptographic Primitives**: AES-256-GCM for credential encryption (FIPS 140-2 compliant)

### Security Guarantees

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Credential Confidentiality** | API keys never leave enclave memory | Hardware memory encryption (SEV-SNP) |
| **Trade Privacy** | Individual trades never transmitted | Data aggregation within enclave boundary |
| **Code Integrity** | Binary matches source | Reproducible builds + attestation |
| **Isolation** | Hypervisor cannot access memory | AMD SEV-SNP VMPL protection |

### Non-Goals

- Protection against timing side-channels (out of scope)
- Protection against physical access to hardware
- Protection against compromised AMD firmware

## Architecture

### System Context

```
┌─────────────────────────────────────────────────────────────┐
│  API Gateway (Untrusted Zone)                               │
│  - HTTP REST API                                            │
│  - Authentication, rate limiting                            │
│  - Access: aggregated data only                             │
│  - Database: hourly_returns, balance_snapshots (READ)       │
└────────────────────────┬────────────────────────────────────┘
                         │ gRPC over mTLS
                         │ Port: 50051 (internal network)
                         ▼
╔═════════════════════════════════════════════════════════════╗
║  Enclave Worker (Trusted Zone - THIS REPOSITORY)            ║
╟─────────────────────────────────────────────────────────────╢
║  AMD SEV-SNP VM (Hardware Isolation)                        ║
║                                                             ║
║  ┌───────────────────────────────────────────────────────┐ ║
║  │  gRPC Server (Port 50051)                             │ ║
║  │  - ProcessSyncJob                                     │ ║
║  │  - CalculateHistoricalReturns                        │ ║
║  │  - GetAggregatedMetrics                              │ ║
║  └───────────────────────────────────────────────────────┘ ║
║                                                             ║
║  ┌───────────────────────────────────────────────────────┐ ║
║  │  Enclave Worker (Orchestrator)                        │ ║
║  │  - Job scheduling                                     │ ║
║  │  - Error handling                                     │ ║
║  │  - Metric aggregation                                 │ ║
║  └───────────────────────────────────────────────────────┘ ║
║                                                             ║
║  ┌───────────────────────────────────────────────────────┐ ║
║  │  Core Services                                        │ ║
║  │  ┌─────────────────────────────────────────────────┐ │ ║
║  │  │  EncryptionService                              │ │ ║
║  │  │  - AES-256-GCM decryption                       │ │ ║
║  │  │  - Key derivation (SHA-256)                     │ │ ║
║  │  └─────────────────────────────────────────────────┘ │ ║
║  │  ┌─────────────────────────────────────────────────┐ │ ║
║  │  │  TradeSyncService                               │ │ ║
║  │  │  - Exchange polling orchestration               │ │ ║
║  │  │  - Deduplication logic                          │ │ ║
║  │  └─────────────────────────────────────────────────┘ │ ║
║  │  ┌─────────────────────────────────────────────────┐ │ ║
║  │  │  EquitySnapshotAggregator                       │ │ ║
║  │  │  - Position reconstruction                      │ │ ║
║  │  │  - P&L calculation (realized + unrealized)      │ │ ║
║  │  │  - Hourly aggregation                           │ │ ║
║  │  └─────────────────────────────────────────────────┘ │ ║
║  └───────────────────────────────────────────────────────┘ ║
║                                                             ║
║  ┌───────────────────────────────────────────────────────┐ ║
║  │  Exchange Connectors                                  │ ║
║  │  - CCXT (Binance, Bitget, MEXC, ByBit)              │ ║
║  │  - Interactive Brokers (IBKR Flex Web API)          │ ║
║  │  - Alpaca Markets (REST API v2)                     │ ║
║  └───────────────────────────────────────────────────────┘ ║
║                                                             ║
║  ┌───────────────────────────────────────────────────────┐ ║
║  │  Database Layer (PostgreSQL)                          │ ║
║  │  - User: enclave_user (full privileges)              │ ║
║  │  - Tables: trades (R/W), hourly_returns (W)          │ ║
║  └───────────────────────────────────────────────────────┘ ║
╚═════════════════════════════════════════════════════════════╝

Output: Aggregated hourly_returns only (no individual trades)
```

### Data Flow

```
External Exchange APIs
         │
         ▼
  ┌──────────────┐
  │ Credentials  │ ◄── AES-256-GCM Decryption (in enclave)
  │ (encrypted)  │
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ Raw Trades   │ ◄── Fetched via HTTPS
  │              │
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ Store in DB  │ ◄── PostgreSQL (trades table)
  │ trades       │     Only enclave has access
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ Aggregate    │ ◄── Position-based calculation
  │ P&L Hourly   │     Realized + Unrealized
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ Store        │ ◄── PostgreSQL (hourly_returns table)
  │ hourly_      │     Gateway can read this
  │ returns      │
  └──────────────┘
         │
         ▼
     Gateway
    (Public API)
```

## Trusted Computing Base

### Size Metrics

| Component | Files | LOC | Purpose |
|-----------|-------|-----|---------|
| **EncryptionService** | 1 | 200 | AES-256-GCM credential decryption |
| **Exchange Connectors** | 3 | 1,400 | CCXT, IBKR, Alpaca integrations |
| **External API Services** | 3 | 1,441 | Trade fetching from exchanges |
| **EquitySnapshotAggregator** | 1 | 731 | Position-based returns calculation |
| **TradeSyncService** | 1 | 400 | Synchronization orchestration |
| **EnclaveRepository** | 1 | 300 | Database access layer |
| **EnclaveWorker + Server** | 2 | 100 | gRPC server and entry point |
| **Total** | **12** | **4,572** | Minimized attack surface |

### Dependencies

Critical dependencies (included in TCB):
- `@prisma/client` (6.15.0) - Database ORM
- `@grpc/grpc-js` (1.14.1) - gRPC implementation
- `ccxt` (4.5.2) - Cryptocurrency exchange integration
- `@stoqey/ib` (1.5.1) - Interactive Brokers API
- `@alpacahq/alpaca-trade-api` (3.1.3) - Alpaca Markets API

Total transitive dependencies: 47 packages

## Threat Model

### In-Scope Threats

1. **Compromised API Gateway**
   - Mitigation: Gateway has no access to trades table (PostgreSQL permissions)

2. **Compromised Hypervisor**
   - Mitigation: AMD SEV-SNP memory encryption prevents hypervisor from reading enclave RAM

3. **Supply Chain Attack**
   - Mitigation: Reproducible builds, package-lock.json pinning, audit trail

4. **Malicious Insider (Infrastructure)**
   - Mitigation: Attestation verifies binary integrity, no debug interfaces in production

### Out-of-Scope Threats

- Compromised AMD SEV-SNP firmware (requires hardware root of trust)
- Physical access to server
- Side-channel attacks (timing, power analysis)
- Denial of Service

### Attack Surface

| Interface | Exposure | Attack Vector | Mitigation |
|-----------|----------|---------------|------------|
| **gRPC API** | Internal network only | Malformed messages | Input validation (Protobuf schema) |
| **PostgreSQL** | Local socket | SQL injection | Parameterized queries (Prisma) |
| **Exchange APIs** | HTTPS outbound | Man-in-the-middle | TLS 1.3, certificate pinning |
| **Dependencies** | npm packages | Malicious packages | Lock file, audit, minimal deps |

## Build Instructions

### Prerequisites

- **Node.js**: 20.11.0 (exact version required for reproducibility)
- **npm**: 10.2.3
- **Operating System**: Linux (Ubuntu 22.04 LTS recommended)
- **Architecture**: x86_64

### Reproducible Build

```bash
# Clone repository
git clone https://github.com/Jimmy7892/track-return-enclave.git
cd track-return-enclave

# Checkout specific version
git checkout v1.0.0

# Verify commit hash
git rev-parse HEAD
# Expected: <COMMIT_HASH>

# Install exact dependencies
npm ci

# Generate Prisma client
npm run prisma:generate

# Build TypeScript
npm run build

# Verify build hash
find dist -type f -name "*.js" -exec sha256sum {} \; | sort -k 2 | sha256sum
# Expected: <BUILD_HASH>
```

See [BUILD.md](BUILD.md) for detailed reproducible build instructions.

## Deployment

### Hardware Requirements

**Production (AMD SEV-SNP)**:
- AMD EPYC 7003 series or newer (Milan)
- SEV-SNP enabled in BIOS
- Minimum 4 vCPU, 8GB RAM
- 50GB SSD storage

**Development (Non-isolated)**:
- Any x86_64 system
- 2 vCPU, 4GB RAM minimum

### Environment Configuration

```bash
# Enclave mode
ENCLAVE_MODE=true          # Enable enclave features
AMD_SEV_SNP=true           # Verify SEV-SNP (production only)

# Database (full access)
DATABASE_URL="postgresql://enclave_user:password@db:5432/aggregator"

# Encryption key (32 bytes, hex-encoded)
ENCRYPTION_KEY="<64-character-hex-string>"

# gRPC server
ENCLAVE_PORT=50051         # Internal network only
```

### Production Deployment

```bash
# Install dependencies
npm ci --only=production

# Build
npm run build

# Run with process manager
pm2 start dist/index.js --name enclave-worker

# Verify attestation (SEV-SNP)
curl http://169.254.169.254/metadata/attestation/report
```

### Database Permissions

```sql
-- Create enclave user with full access
CREATE USER enclave_user WITH PASSWORD '<strong-password>';
GRANT ALL PRIVILEGES ON DATABASE aggregator TO enclave_user;

-- Grant access to tables
GRANT ALL ON trades, hourly_returns, balance_snapshots TO enclave_user;

-- Verify permissions
\du enclave_user
```

## Audit Process

### Scope

This repository is designed for independent security audits. Auditors should verify:

1. **Code Review**: No backdoors, credential leaks, or unsafe operations
2. **Cryptographic Implementation**: Proper use of AES-256-GCM
3. **Input Validation**: All external inputs sanitized
4. **Output Sanitization**: No individual trades in aggregated results
5. **Reproducible Builds**: Binary matches source code

### Audit Checklist

- [ ] Review all credential handling in `EncryptionService`
- [ ] Verify no logging of sensitive data (credentials, trades)
- [ ] Confirm database queries use parameterized statements
- [ ] Check all exchange API calls use HTTPS with certificate validation
- [ ] Verify aggregation logic prevents individual trade leakage
- [ ] Test build reproducibility on clean Ubuntu 22.04 VM
- [ ] Review all dependencies for known vulnerabilities (`npm audit`)
- [ ] Verify gRPC API only returns aggregated data
- [ ] Check SEV-SNP attestation implementation (if deployed)

### Previous Audits

| Date | Auditor | Version | Status | Report |
|------|---------|---------|--------|--------|
| TBD | TBD | v1.0.0 | Pending | - |

### Responsible Disclosure

Security vulnerabilities should be reported privately to:
- **Email**: security@trackrecord.com
- **PGP Key**: [Available on request]

Please do **not** open public GitHub issues for security vulnerabilities.

## API Specification

### gRPC Service Definition

```protobuf
service EnclaveService {
  rpc ProcessSyncJob(SyncJobRequest) returns (SyncJobResponse);
  rpc CalculateHistoricalReturns(HistoricalReturnsRequest) returns (HistoricalReturnsResponse);
  rpc GetAggregatedMetrics(AggregatedMetricsRequest) returns (AggregatedMetricsResponse);
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}
```

See [src/proto/enclave.proto](src/proto/enclave.proto) for full specification.

### Example Usage

```javascript
const client = new EnclaveClient('localhost:50051');

// Request sync job
const response = await client.processSyncJob({
  userUid: 'user_123',
  exchange: 'binance',
  type: 'INCREMENTAL'
});

// Response contains ONLY aggregated data
console.log(response.hourlyReturnsGenerated); // 24
console.log(response.latestSnapshot.balance);  // 10000.00
// Individual trades are NEVER returned
```

## Performance Characteristics

| Operation | Latency (p95) | Throughput |
|-----------|---------------|------------|
| Decrypt credentials | < 5ms | N/A |
| Fetch trades (1000 trades) | < 2s | Depends on exchange |
| Aggregate to hourly | < 100ms per hour | ~10 hours/sec |
| gRPC call overhead | < 10ms | N/A |

Measured on AMD EPYC 7003, 4 vCPU, 8GB RAM.

## Compliance

- **GDPR**: Individual trades processed in enclave, not stored outside EU (if deployed in EU)
- **SOC 2 Type II**: Audit controls for data processing (in progress)
- **FIPS 140-2**: Cryptographic primitives (AES-256-GCM via Node.js crypto module)

## References

- [AMD SEV-SNP Whitepaper](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)
- [CCXT Documentation](https://docs.ccxt.com/)
- [Interactive Brokers Flex Web API](https://www.interactivebrokers.com/en/software/am/am/reports/flex_web_service_version_3.htm)
- [gRPC Best Practices](https://grpc.io/docs/guides/performance/)

## License

MIT License - See [LICENSE](LICENSE)

## Contributing

This is a security-critical component. Contributions are welcome but will be thoroughly reviewed.

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

All commits must be signed (GPG).

## Contact

- **Project Website**: https://trackrecord.com
- **Security Email**: security@trackrecord.com
- **GitHub Issues**: https://github.com/Jimmy7892/track-return-enclave/issues