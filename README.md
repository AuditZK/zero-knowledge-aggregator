# Track Record Enclave Worker

**Trusted Computing Base for Confidential Trading Data Aggregation**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TCB](https://img.shields.io/badge/TCB-5,454%20LOC-green.svg)]()
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
│  - Database: snapshot_data (READ)                           │
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
║  │  Autonomous Daily Sync Scheduler (00:00 UTC)         │ ║
║  │  - DailySyncSchedulerService (node-cron)             │ ║
║  │  - Triggers daily snapshots for ALL active users     │ ║
║  │  - Rate-limited (23h cooldown per user/exchange)     │ ║
║  │  - Audit trail: SyncRateLimitLog table               │ ║
║  └───────────────────────────────────────────────────────┘ ║
║                                                             ║
║  ┌───────────────────────────────────────────────────────┐ ║
║  │  gRPC Server (Port 50051)                             │ ║
║  │  - ProcessSyncJob (manual sync)                      │ ║
║  │  - GetAggregatedMetrics                              │ ║
║  │  - HealthCheck                                       │ ║
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
║  │  │  - Equity snapshot creation (daily at 00:00)    │ │ ║
║  │  │  - P&L calculation (realized + unrealized)      │ │ ║
║  │  │  - Deposit/withdrawal tracking                  │ │ ║
║  │  └─────────────────────────────────────────────────┘ │ ║
║  │  ┌─────────────────────────────────────────────────┐ │ ║
║  │  │  SyncRateLimiterService (src/services/)         │ │ ║
║  │  │  - 23-hour cooldown enforcement                 │ │ ║
║  │  │  - Prevents cherry-picking via manual API calls │ │ ║
║  │  │  - Audit trail for systematic snapshot proof    │ │ ║
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
║  │  - Tables: trades (R/W), snapshot_data (W)           │ ║
║  │  - Audit: sync_rate_limit_logs (R/W)                 │ ║
║  │  - All queries parameterized (Prisma ORM)            │ ║
║  └───────────────────────────────────────────────────────┘ ║
╚═════════════════════════════════════════════════════════════╝

Output: Aggregated daily snapshots only (no individual trades)
Autonomous: Daily sync at 00:00 UTC for all active users
```

### Data Flow

```
┌─────────────────────────────────────────────────────────┐
│  AUTONOMOUS SCHEDULER (00:00 UTC daily)                 │
│  ┌──────────────────────────────────────────────────┐   │
│  │  DailySyncSchedulerService (node-cron)           │   │
│  │  1. Get all active users from database           │   │
│  │  2. For each user, get active exchange conns     │   │
│  │  3. Check rate limit (23h cooldown)              │   │
│  │  4. Trigger snapshot creation                    │   │
│  │  5. Record sync in audit log                     │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
         │
         ▼
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
  │ Current      │ ◄── Fetched via HTTPS (TLS 1.3)
  │ Account      │     Total equity, realized balance, unrealized P&L
  │ State        │     Deposits/withdrawals detection
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ Create Daily │ ◄── EquitySnapshotAggregator
  │ Snapshot     │     Timestamp: 00:00 UTC
  └──────────────┘     Fields: totalEquity, realizedBalance, unrealizedPnL,
         │               deposits, withdrawals, breakdown_by_market
         ▼
  ┌──────────────┐
  │ Store        │ ◄── PostgreSQL snapshot_data table
  │ snapshot_    │     Gateway has SELECT access
  │ data         │     No individual trades visible
  └──────────────┘     One snapshot per day per user/exchange
         │
         ▼
  ┌──────────────┐
  │ Rate Limiter │ ◄── SyncRateLimiterService
  │ Audit Log    │     Records sync timestamp
  └──────────────┘     Prevents manual cherry-picking
         │
         ▼
  API Gateway (untrusted) → Frontend (public)
```

### Critical Security Properties

1. **Zero-Knowledge Architecture**: Individual trades are NEVER transmitted outside the enclave. Only aggregated daily snapshots (total equity, P&L) cross the enclave boundary via gRPC. The API Gateway (and thus any attacker who compromises it) sees ONLY daily summaries, never individual trades or prices.

2. **Autonomous Systematic Snapshots**: The scheduler runs inside the hardware-attested enclave at 00:00 UTC daily, ensuring snapshots are taken systematically and cannot be cherry-picked at favorable market conditions. The rate limiter enforces a 23-hour cooldown, preventing manual API abuse.

3. **Audit Trail**: All sync operations are logged in `sync_rate_limit_logs` table with timestamps, proving that snapshots were created systematically by the enclave scheduler, not manually triggered to hide losses.

## Trusted Computing Base

### Size Metrics

| Component | Files | LOC | Purpose |
|-----------|-------|-----|---------|
| **EncryptionService** | 1 | 200 | AES-256-GCM credential decryption |
| **Exchange Connectors** | 3 | 1,400 | CCXT, IBKR, Alpaca integrations |
| **External API Services** | 3 | 1,441 | Account state fetching from exchanges |
| **EquitySnapshotAggregator** | 1 | 731 | Daily snapshot creation with P&L |
| **TradeSyncService** | 1 | 400 | Synchronization orchestration |
| **DailySyncSchedulerService** | 1 | 220 | Autonomous cron scheduler (00:00 UTC) |
| **SyncRateLimiterService** | 1 | 202 | Rate limiting & audit trail |
| **Repositories** | 6 | 760 | Database access layer |
| **EnclaveWorker + Server** | 2 | 100 | gRPC server and entry point |
| **Total** | **19** | **5,454** | Minimized attack surface |

**Rationale for TCB size**: By isolating only the code that MUST handle credentials and create snapshots, we reduce the attack surface from ~12,000 LOC (full platform) to 5,454 LOC (enclave only). This makes security audits tractable and reduces the probability of vulnerabilities. The autonomous scheduler and rate limiter are included in the TCB to prove snapshot integrity via hardware attestation.

### Dependencies

Critical dependencies (included in TCB audit scope):

| Package | Version | Purpose | CVEs |
|---------|---------|---------|------|
| `@prisma/client` | 6.15.0 | Database ORM (parameterized queries) | None |
| `@grpc/grpc-js` | 1.14.1 | gRPC implementation | None |
| `ccxt` | 4.5.2 | Cryptocurrency exchange integration | None |
| `@stoqey/ib` | 1.5.1 | Interactive Brokers API | None |
| `@alpacahq/alpaca-trade-api` | 3.1.3 | Alpaca Markets API | None |
| `node-cron` | 3.0.3 | Autonomous scheduler (00:00 UTC daily) | None |
| `tsyringe` | 4.10.0 | Dependency injection | None |
| `winston` | 3.17.0 | Logging (sensitive data redacted) | None |

Total transitive dependencies: 49 packages (audited with `npm audit`)

## Threat Model

### In-Scope Threats

#### 1. Compromised API Gateway
**Threat**: Attacker gains control of the API Gateway service.

**Impact**: WITHOUT enclave isolation, attacker could access all individual trades and credentials.

**Mitigation**:
- Gateway runs outside enclave with restricted database access
- PostgreSQL permissions prevent gateway_user from reading `trades` table
- Gateway only receives aggregated daily snapshots via gRPC
- Rate limiter audit logs prove snapshots are systematic, not cherry-picked

**Verification**: Auditors should verify that Gateway code (not in this repo) cannot access sensitive tables or bypass rate limiting.

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

**Snapshot Privacy:**
- [ ] Review `src/services/equity-snapshot-aggregator.ts` snapshot creation logic
- [ ] Verify gRPC responses (see `src/enclave-server.ts`) contain only aggregated data
- [ ] Check no individual trades in snapshot_data table
- [ ] Confirm no trade detail in logs (search for `logger.debug` with trade data)
- [ ] Review `src/services/sync-rate-limiter.service.ts` for rate limit enforcement
- [ ] Verify `sync_rate_limit_logs` audit trail prevents cherry-picking
- [ ] Check `src/services/daily-sync-scheduler.service.ts` runs at 00:00 UTC systematically

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

#### ProcessSyncJob Response Structure

```javascript
{
  success: true,
  userUid: "user123",
  exchange: "binance",
  synced: true,
  latestSnapshot: {
    // Aggregated daily snapshot (00:00 UTC)
    totalEquity: 10500.00,          // Total account value (realized + unrealized)
    realizedBalance: 10250.42,      // Available cash/balance
    unrealizedPnL: 249.58,          // Unrealized P&L from open positions
    deposits: 0,                    // Cash deposited today
    withdrawals: 0,                 // Cash withdrawn today
    timestamp: "2025-01-15T00:00:00Z"  // Daily snapshot timestamp
  }
  // NO individual trades array
  // NO trade prices
  // NO trade timestamps
  // NO position sizes
}
```

#### GetAggregatedMetrics Response Structure

```javascript
{
  totalBalance: 10250.42,         // Total realized balance across all exchanges
  totalEquity: 10500.00,          // Total equity (realized + unrealized)
  totalRealizedPnl: 500.00,       // Cumulative realized P&L
  totalUnrealizedPnl: 249.58,     // Current unrealized P&L
  totalFees: 25.50,               // Cumulative fees paid
  totalTrades: 150,               // Count only (no trade details)
  lastSync: "2025-01-15T00:00:00Z"  // Timestamp of last snapshot
  // NO individual trades
  // NO exchange-specific breakdown with identifying details
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