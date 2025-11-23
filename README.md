# Track Record Enclave Worker

**Trusted Computing Base for Confidential Trading Data Aggregation**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TCB](https://img.shields.io/badge/TCB-4,572%20LOC-green.svg)]()
[![Node.js](https://img.shields.io/badge/Node.js-20.x-339933.svg)]()
[![AMD SEV-SNP](https://img.shields.io/badge/AMD-SEV--SNP-red.svg)]()

## Overview

This repository contains the **Trusted Computing Base (TCB)** of the Track Record platform's data aggregation service. It implements a zero-knowledge architecture for processing sensitive trading data within an AMD SEV-SNP hardware-isolated enclave.

**This repository serves two purposes:**

1. **Primary Development Repository**: This is where the Enclave Worker code is actively developed. All enclave features are built and tested here.

2. **Public Audit & Verification**: The code is published for independent security audits and reproducible build verification. This enables auditors to verify that the production binary matches the audited source code.

**For development instructions**, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Table of Contents

- [Security Model](#security-model)
- [Architecture](#architecture)
- [Trusted Computing Base](#trusted-computing-base)
- [Threat Model](#threat-model)
- [Audit Process](#audit-process)
- [Reproducible Builds](#reproducible-builds)
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
| **Code Integrity** | Binary matches audited source | Reproducible builds + attestation |
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
│  - HTTP REST API (public-facing)                            │
│  - Authentication, rate limiting                            │
│  - Access: aggregated data only                             │
│  - Database: hourly_returns, balance_snapshots (READ)       │
│  - Code: NOT in this repository (proprietary)               │
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
║  │  - GetAggregatedMetrics                              │ ║
║  └───────────────────────────────────────────────────────┘ ║
║                                                             ║
║  ┌───────────────────────────────────────────────────────┐ ║
║  │  Core Services                                        │ ║
║  │  ┌─────────────────────────────────────────────────┐ │ ║
║  │  │  EncryptionService (src/services/)              │ │ ║
║  │  │  - AES-256-GCM credential decryption            │ │ ║
║  │  │  - Key derivation (SHA-256)                     │ │ ║
║  │  │  - No key logging or persistence                │ │ ║
║  │  └─────────────────────────────────────────────────┘ │ ║
║  │  ┌─────────────────────────────────────────────────┐ │ ║
║  │  │  TradeSyncService (src/services/)               │ │ ║
║  │  │  - Exchange polling orchestration               │ │ ║
║  │  │  - Trade deduplication                          │ │ ║
║  │  └─────────────────────────────────────────────────┘ │ ║
║  │  ┌─────────────────────────────────────────────────┐ │ ║
║  │  │  EquitySnapshotAggregator (src/services/)       │ │ ║
║  │  │  - Position reconstruction from trades          │ │ ║
║  │  │  - P&L calculation (realized + unrealized)      │ │ ║
║  │  │  - Hourly aggregation (destroys trade detail)   │ │ ║
║  │  └─────────────────────────────────────────────────┘ │ ║
║  └───────────────────────────────────────────────────────┘ ║
║                                                             ║
║  ┌───────────────────────────────────────────────────────┐ ║
║  │  Exchange Connectors (src/connectors/)                │ ║
║  │  - CcxtExchangeConnector (Binance, Bitget, MEXC)     │ ║
║  │  - IbkrFlexConnector (Interactive Brokers)           │ ║
║  │  - AlpacaConnector (Alpaca Markets)                  │ ║
║  └───────────────────────────────────────────────────────┘ ║
║                                                             ║
║  ┌───────────────────────────────────────────────────────┐ ║
║  │  Database Layer (src/repositories/)                   │ ║
║  │  - User: enclave_user (full privileges)              │ ║
║  │  - Tables: trades (R/W), hourly_returns (W)          │ ║
║  │  - All queries parameterized (Prisma ORM)            │ ║
║  └───────────────────────────────────────────────────────┘ ║
╚═════════════════════════════════════════════════════════════╝

Output: Aggregated hourly_returns only (no individual trades)
```

### Data Flow

```
External Exchange APIs (Binance, IBKR, Alpaca)
         │
         ▼
  ┌──────────────┐
  │ Credentials  │ ◄── Retrieved encrypted from PostgreSQL
  │ (encrypted)  │     AES-256-GCM decryption IN ENCLAVE
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ Raw Trades   │ ◄── Fetched via HTTPS (TLS 1.3)
  │              │     Individual fills, prices, timestamps
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ Store in DB  │ ◄── PostgreSQL trades table
  │ trades       │     Only enclave_user has SELECT access
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ Aggregate    │ ◄── Position-based P&L calculation
  │ P&L Hourly   │     Realized + Unrealized per hour
  └──────────────┘     Individual trade detail DESTROYED
         │
         ▼
  ┌──────────────┐
  │ Store        │ ◄── PostgreSQL hourly_returns table
  │ hourly_      │     Gateway has SELECT access
  │ returns      │     No individual trades visible
  └──────────────┘
         │
         ▼
  API Gateway (untrusted) → Frontend (public)
```

### Critical Security Property

**Zero-Knowledge Architecture**: Individual trades are processed within the enclave and aggregated into hourly returns. Only aggregated data crosses the enclave boundary via gRPC. The API Gateway (and thus any attacker who compromises it) sees ONLY hourly summaries, never individual trades or prices.

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

**Rationale for TCB size**: By isolating only the code that MUST handle credentials and individual trades, we reduce the attack surface from ~12,000 LOC (full platform) to 4,572 LOC (enclave only). This makes security audits tractable and reduces the probability of vulnerabilities.

### Dependencies

Critical dependencies (included in TCB audit scope):

| Package | Version | Purpose | CVEs |
|---------|---------|---------|------|
| `@prisma/client` | 6.15.0 | Database ORM (parameterized queries) | None |
| `@grpc/grpc-js` | 1.14.1 | gRPC implementation | None |
| `ccxt` | 4.5.2 | Cryptocurrency exchange integration | None |
| `@stoqey/ib` | 1.5.1 | Interactive Brokers API | None |
| `@alpacahq/alpaca-trade-api` | 3.1.3 | Alpaca Markets API | None |
| `tsyringe` | 4.10.0 | Dependency injection | None |
| `winston` | 3.17.0 | Logging (sensitive data redacted) | None |

Total transitive dependencies: 47 packages (audited with `npm audit`)

## Threat Model

### In-Scope Threats

#### 1. Compromised API Gateway
**Threat**: Attacker gains control of the API Gateway service.

**Impact**: WITHOUT enclave isolation, attacker could access all individual trades and credentials.

**Mitigation**:
- Gateway runs outside enclave with restricted database access
- PostgreSQL permissions prevent gateway_user from reading `trades` table
- Gateway only receives aggregated hourly_returns via gRPC

**Verification**: Auditors should verify that Gateway code (not in this repo) cannot access sensitive tables.

#### 2. Compromised Hypervisor
**Threat**: Malicious cloud provider or attacker compromises the VM hypervisor.

**Impact**: WITHOUT SEV-SNP, hypervisor could read enclave memory and steal credentials.

**Mitigation**:
- AMD SEV-SNP encrypts VM memory with keys inaccessible to hypervisor
- Memory encryption uses AES-128 with ephemeral keys per VM
- Attestation verifies enclave binary integrity before credential decryption

**Verification**: Auditors should verify that SEV-SNP attestation is checked on enclave startup (see `src/config/enclave-container.ts`).

#### 3. Supply Chain Attack
**Threat**: Malicious code injected via compromised npm package.

**Impact**: Attacker could exfiltrate credentials or trades.

**Mitigation**:
- `package-lock.json` pins exact dependency versions and hashes
- Reproducible builds allow verification that deployed binary matches audited source
- Regular `npm audit` checks for known vulnerabilities

**Verification**: Auditors should review `package-lock.json` integrity hashes and check for suspicious dependencies.

#### 4. Malicious Insider (Infrastructure)
**Threat**: Insider with access to production infrastructure attempts to extract sensitive data.

**Impact**: WITHOUT attestation, insider could deploy modified enclave code.

**Mitigation**:
- SEV-SNP attestation report verifies binary hash before Gateway connects
- Debug interfaces disabled in production build
- All enclave access logged (audit trail)

**Verification**: Auditors should verify no debug endpoints exist in production code paths.

### Out-of-Scope Threats

- **Compromised AMD SEV-SNP firmware**: Requires hardware root of trust
- **Physical access to server**: Physical security is operational concern
- **Side-channel attacks**: Timing/power analysis out of scope
- **Denial of Service**: Availability is separate from confidentiality

### Attack Surface

| Interface | Exposure | Attack Vector | Mitigation | Audit Focus |
|-----------|----------|---------------|------------|-------------|
| **gRPC API** | Internal network only | Malformed messages | Protobuf schema validation | Verify no unauthenticated endpoints |
| **PostgreSQL** | Local socket | SQL injection | Parameterized queries (Prisma ORM) | Review all query construction |
| **Exchange APIs** | HTTPS outbound | MitM, response manipulation | TLS 1.3, response validation | Check TLS config, input sanitization |
| **Dependencies** | npm packages | Malicious code | Lock file pinning, audit | Review package-lock.json hashes |

## Audit Process

### Scope

This repository is designed for independent security audits. Auditors should focus on:

1. **Credential Handling**: Verify credentials are decrypted only in-memory and never logged
2. **Trade Privacy**: Confirm individual trades never leave enclave boundary
3. **Cryptographic Correctness**: Review AES-256-GCM implementation
4. **Input Validation**: Check all external inputs (gRPC, exchange APIs) are sanitized
5. **Output Sanitization**: Ensure aggregated data contains no individual trade details
6. **Reproducible Builds**: Verify deployed binary matches source code

### Audit Checklist

**Credential Security:**
- [ ] Review `src/services/encryption-service.ts` for key derivation and AES-GCM usage
- [ ] Verify no credentials logged in `src/utils/logger.ts` or `src/utils/logger.service.ts`
- [ ] Check credentials are not persisted decrypted (grep for `writeFile`, `console.log`)
- [ ] Confirm decrypted credentials stored only in enclave RAM (no global variables)

**Trade Privacy:**
- [ ] Review `src/services/equity-snapshot-aggregator.ts` aggregation logic
- [ ] Verify gRPC responses (see `src/enclave-server.ts`) contain only aggregated data
- [ ] Check no individual trades in hourly_returns calculation
- [ ] Confirm no trade detail in logs (search for `logger.debug` with trade data)

**Input Validation:**
- [ ] Review gRPC message validation in `src/enclave-server.ts`
- [ ] Check exchange API response parsing in `src/external/` (ccxt, ibkr, alpaca)
- [ ] Verify Prisma queries in `src/repositories/enclave-repository.ts` use parameterized statements
- [ ] Test for SQL injection vectors (manual or automated)

**Dependencies:**
- [ ] Run `npm audit` and review results
- [ ] Check `package-lock.json` integrity hashes
- [ ] Review critical dependencies: `ccxt`, `@stoqey/ib`, `@alpacahq/alpaca-trade-api`
- [ ] Verify no suspicious packages in transitive dependencies

**Build Verification:**
- [ ] Clone repository and build on clean Ubuntu 22.04 VM
- [ ] Verify build hash matches published hash
- [ ] Review build process in `tsconfig.json` for suspicious flags
- [ ] Check for source map exposure (production builds should not include source maps)

### Recommended Tools

- **Static Analysis**: ESLint, TypeScript strict mode (enabled in `tsconfig.json`)
- **Dependency Scanning**: `npm audit`, Snyk, GitHub Dependabot
- **Secret Detection**: GitLeaks, TruffleHog
- **Code Review**: Manual review with security focus

### Previous Audits

| Date | Auditor | Version | Status | Report |
|------|---------|---------|--------|--------|
| TBD | TBD | v1.0.0 | Pending | - |

### Responsible Disclosure

Security vulnerabilities should be reported privately to:
- **Email**: security@trackrecord.com
- **Response SLA**: 48 hours for acknowledgment, 7 days for initial assessment

Please **do not** open public GitHub issues for security vulnerabilities.

## Reproducible Builds

### Purpose

Reproducible builds allow verification that the binary running in production matches the audited source code. This prevents the "trusting trust" problem where source code is clean but deployed binary is compromised.

### Build Process

```bash
# Clone repository
git clone https://github.com/Jimmy7892/track-return-enclave.git
cd track-return-enclave

# Checkout specific version
git checkout v1.0.0

# Verify commit hash
git rev-parse HEAD
# Expected: 0622144abcdef... (published on release page)

# Install exact dependencies
npm ci

# Generate Prisma client
npm run prisma:generate

# Build TypeScript
npm run build

# Calculate build hash
find dist -type f -name "*.js" -exec sha256sum {} \; | sort -k 2 | sha256sum
# Expected: <BUILD_HASH> (published on release page)
```

### Build Environment

For bit-for-bit reproducibility:
- **Node.js**: 20.11.0 (exact version)
- **npm**: 10.2.3
- **OS**: Ubuntu 22.04 LTS (Linux kernel 5.15+)
- **Architecture**: x86_64
- **Locale**: `LANG=C.UTF-8`

Detailed instructions: [BUILD.md](BUILD.md)

### Attestation (Production Only)

In production deployments on AMD SEV-SNP:

1. Enclave generates attestation report containing:
   - Binary hash (SHA-256)
   - VM measurement
   - SEV-SNP firmware version

2. API Gateway verifies attestation before connecting to enclave

3. Attestation report can be independently verified by auditors

**Note**: Attestation is only available on AMD SEV-SNP hardware, not in development environments.

## API Specification

### gRPC Service Definition

```protobuf
service EnclaveService {
  // Process sync job for a user's exchanges
  // Returns: Aggregated snapshot data (NOT individual trades)
  rpc ProcessSyncJob(SyncJobRequest) returns (SyncJobResponse);

  // Get aggregated metrics
  // Returns: Summary statistics (balance, P&L totals)
  rpc GetAggregatedMetrics(AggregatedMetricsRequest)
      returns (AggregatedMetricsResponse);

  // Health check
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}
```

Full specification: [src/proto/enclave.proto](src/proto/enclave.proto)

### Security Properties of API

**Critical**: All gRPC responses contain ONLY aggregated data. Individual trade prices, timestamps, or sizes are NEVER transmitted outside the enclave.

Example response structure:
```javascript
{
  success: true,
  hourlyReturnsGenerated: 24,  // Count only
  latestSnapshot: {
    balance: 10250.42,           // Total balance
    equity: 10500.00,            // Total equity
    timestamp: "2025-01-15T12:00:00Z"
  }
  // NO individual trades array
  // NO trade prices
  // NO trade timestamps
}
```

## Compliance

- **GDPR Article 32** (Security of processing): Technical measures to protect personal data
- **FIPS 140-2 Level 1**: Cryptographic primitives (AES-256-GCM via Node.js crypto module)
- **SOC 2 Type II**: Audit controls for data processing (in progress)

## References

- [AMD SEV-SNP Whitepaper](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)
- [CCXT Documentation](https://docs.ccxt.com/)
- [Interactive Brokers Flex Web API](https://www.interactivebrokers.com/en/software/am/am/reports/flex_web_service_version_3.htm)
- [gRPC Security Guide](https://grpc.io/docs/guides/auth/)
- [Reproducible Builds Project](https://reproducible-builds.org/)

## License

MIT License - See [LICENSE](LICENSE)

This code is published for transparency and audit purposes. Third-party deployment is not supported.

## Contact

- **Security Email**: security@trackrecord.com (for vulnerabilities)
- **GitHub Issues**: https://github.com/Jimmy7892/track-return-enclave/issues (for code questions)