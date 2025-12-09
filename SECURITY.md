# Security Documentation

**Track Record Enclave - Confidential Trading Data Aggregation**

This document describes the security architecture, mechanisms, and guarantees of the Track Record Enclave Worker.

---

## Table of Contents

- [Security Overview](#security-overview)
- [Zero-Knowledge Architecture](#zero-knowledge-architecture)
- [Hardware Isolation (AMD SEV-SNP)](#hardware-isolation-amd-sev-snp)
- [Cryptographic Protection](#cryptographic-protection)
- [Secure Logging System](#secure-logging-system)
- [Memory Protection](#memory-protection)
- [Database Security](#database-security)
- [Rate Limiting & Anti-Manipulation](#rate-limiting--anti-manipulation)
- [Audit Trail](#audit-trail)
- [Threat Model](#threat-model)
- [Security Guarantees](#security-guarantees)
- [Compliance](#compliance)

---

## Security Overview

The Track Record Enclave implements a **zero-knowledge architecture** for processing sensitive trading data. The system is designed with the following core security principles:

1. **Hardware Root of Trust**: AMD SEV-SNP provides memory encryption and attestation
2. **Minimal Trust Boundary**: Only ~6,400 LOC in the Trusted Computing Base (TCB)
3. **Data Minimization**: Individual trades never leave the enclave
4. **Defense in Depth**: Multiple layers of security controls
5. **Auditability**: All security mechanisms are auditable and reproducible

---

## Zero-Knowledge Architecture

### Principle

**NO individual trading data ever leaves the enclave boundary.**

The enclave processes sensitive data (API credentials, individual trades, positions) but only outputs **aggregated daily snapshots** containing:
- Total equity
- Realized balance
- Unrealized P&L
- Deposits/withdrawals (cash flow)

### Data Flow Isolation

```
┌─────────────────────────────────────────────────────────┐
│  INSIDE ENCLAVE (AMD SEV-SNP Protected Memory)          │
│  ┌────────────────────────────────────────────┐         │
│  │  Encrypted Credentials (AES-256-GCM)       │         │
│  │  - API Keys, Secrets, Passphrases          │         │
│  │  - Decrypted ONLY in enclave memory        │         │
│  └────────────────────────────────────────────┘         │
│                     │                                    │
│                     ▼                                    │
│  ┌────────────────────────────────────────────┐         │
│  │  Individual Trades (NEVER transmitted)     │         │
│  │  - Trade prices, timestamps, sizes         │         │
│  │  - Position details                        │         │
│  │  - Account balances by market              │         │
│  └────────────────────────────────────────────┘         │
│                     │                                    │
│                     ▼                                    │
│  ┌────────────────────────────────────────────┐         │
│  │  Aggregation Engine                        │         │
│  │  - Daily snapshots at 00:00 UTC            │         │
│  │  - P&L calculation                         │         │
│  │  - Deposit/withdrawal detection            │         │
│  └────────────────────────────────────────────┘         │
│                     │                                    │
└─────────────────────┼────────────────────────────────────┘
                      │
                      ▼ ENCLAVE BOUNDARY (gRPC over mTLS)
                      │
            ┌─────────────────────┐
            │  Aggregated Data    │
            │  ONLY (safe to exit)│
            │  - Total equity     │
            │  - Realized balance │
            │  - Unrealized P&L   │
            │  - Deposits/withdrawals
            └─────────────────────┘
                      │
                      ▼
            API Gateway (Untrusted Zone)
```

### Security Properties

| Data Type | Inside Enclave | Crosses Boundary | Available to API Gateway |
|-----------|----------------|------------------|--------------------------|
| **API Credentials** | ✅ Decrypted | ❌ NEVER | ❌ NEVER |
| **Individual Trades** | ✅ Processed | ❌ NEVER | ❌ NEVER |
| **Trade Prices** | ✅ Used for P&L | ❌ NEVER | ❌ NEVER |
| **Position Sizes** | ✅ Aggregated | ❌ NEVER | ❌ NEVER |
| **Daily Equity Snapshots** | ✅ Created | ✅ YES | ✅ YES (read-only) |
| **Total P&L** | ✅ Calculated | ✅ YES | ✅ YES (read-only) |

---

## Hardware Isolation (AMD SEV-SNP)

### AMD SEV-SNP Protection

The enclave runs inside an **AMD Secure Encrypted Virtualization - Secure Nested Paging (SEV-SNP)** virtual machine, which provides:

#### 1. Memory Encryption
- **AES-128-ECB** encryption of all VM memory
- **Ephemeral keys** generated per VM (inaccessible to hypervisor)
- **DMA protection** prevents direct memory access attacks

#### 2. Attestation
The enclave generates cryptographically signed attestation reports that prove:
- The binary hash matches audited source code
- The VM is running on genuine AMD SEV-SNP hardware
- Memory encryption is active
- The hypervisor cannot access enclave memory

#### 3. Attestation Implementation

Location: [src/services/sev-snp-attestation.service.ts](src/services/sev-snp-attestation.service.ts)

**Supported Platforms:**
- **Bare Metal / KVM**: `/dev/sev-guest` device
- **Azure Confidential VMs**: IMDS attestation endpoint
- **GCP Confidential VMs**: Metadata server attestation

**Attestation Process:**

```typescript
// 1. Check if SEV-SNP is available
isSevSnpAvailable() {
  - Check AMD_SEV_SNP environment variable
  - Check for /dev/sev-guest device
  - Verify CPU capabilities in /proc/cpuinfo
}

// 2. Fetch attestation report
getAttestationReport() {
  - Platform-specific attestation retrieval
  - Contains: measurement, signature, platform version, chip ID
}

// 3. Verify cryptographic signature
verifySignature(report) {
  - Fetch VCEK public key from AMD Key Distribution Service
  - Verify ECDSA signature using SHA-384
  - Validate report data integrity
}
```

**Verification Output:**

```json
{
  "verified": true,
  "enclave": true,
  "sevSnpEnabled": true,
  "measurement": "a3f5...b8c2",  // SHA-384 hash of enclave binary
  "platformVersion": "3",
  "reportData": null
}
```

#### 4. Threat Mitigation

| Threat | Without SEV-SNP | With SEV-SNP |
|--------|-----------------|--------------|
| **Malicious Hypervisor** | Can read all VM memory | Cannot decrypt memory |
| **Cold Boot Attack** | Memory readable after shutdown | Memory encrypted with ephemeral keys |
| **DMA Attack** | Device can access VM memory | DMA protection blocks access |
| **VM Migration Attack** | Memory exposed during migration | Attestation fails if migrated |

---

## Cryptographic Protection

### Encryption Service

Location: [src/services/encryption-service.ts](src/services/encryption-service.ts)

#### Algorithm: AES-256-GCM

**Properties:**
- **Symmetric encryption**: 256-bit keys (FIPS 140-2 compliant)
- **Authenticated encryption**: Galois/Counter Mode (GCM) provides integrity
- **IV (Initialization Vector)**: 16 bytes random per encryption
- **Authentication Tag**: 16 bytes for tamper detection

**Why AES-256-GCM?**
- ✅ Industry standard for confidential data
- ✅ Hardware acceleration (AES-NI on modern CPUs)
- ✅ Authenticated encryption prevents tampering
- ✅ NIST approved (SP 800-38D)

#### Key Derivation (AMD SEV-SNP Hardware)

```typescript
// Master key derived from AMD SEV-SNP hardware measurement
// NO secrets in environment variables
const attestation = await attestationService.getAttestationReport();
const measurement = attestation.measurement; // SHA-384 hash of enclave code

// Derive master key using HKDF-SHA256
const masterKey = crypto.hkdfSync(
  'sha256',
  measurementBuffer,     // From AMD hardware
  salt,                  // Platform version
  'track-record-enclave-dek',
  32                     // 256 bits
);
```

**Security:**
- Master key derived from AMD SEV-SNP hardware measurement (NOT environment variables)
- Key changes automatically when enclave code is updated
- Key never stored - derived on-demand from hardware
- NO FALLBACK: AMD SEV-SNP hardware is REQUIRED

#### Encryption Format

```
[IV (16 bytes)] + [Auth Tag (16 bytes)] + [Encrypted Data (variable)]
      ↓                   ↓                        ↓
   Random            Integrity              Ciphertext
   per message       protection             (API keys, secrets)
```

#### Credential Storage

**Database Schema:**
```sql
CREATE TABLE exchange_connections (
  encrypted_api_key      TEXT NOT NULL,  -- AES-256-GCM encrypted
  encrypted_api_secret   TEXT NOT NULL,  -- AES-256-GCM encrypted
  encrypted_passphrase   TEXT,           -- AES-256-GCM encrypted (optional)
  credentials_hash       TEXT            -- SHA-256 hash for deduplication
);
```

**Decryption Process:**
```typescript
// Credentials decrypted ONLY in enclave memory
const apiKey = EncryptionService.decrypt(encryptedApiKey);
const apiSecret = EncryptionService.decrypt(encryptedApiSecret);

// Used for exchange API authentication
const exchange = new ccxt.binance({
  apiKey,      // In-memory only
  secret: apiSecret,  // In-memory only
});

// Credentials NEVER logged (see Secure Logging)
// Credentials NEVER transmitted outside enclave
```

**Credentials Hash (Deduplication):**
```typescript
// SHA-256 hash to detect duplicate credentials without storing plaintext
const hash = crypto.createHash('sha256')
  .update(`${apiKey}:${apiSecret}:${passphrase}`)
  .digest('hex');
```

---

## Secure Logging System

### Design Philosophy

The logging system implements **deterministic multi-tier redaction** to ensure NO sensitive data ever leaves the enclave, even in logs.

Location: [src/utils/secure-enclave-logger.ts](src/utils/secure-enclave-logger.ts)

### Two-Tier Redaction (ALWAYS Active)

#### TIER 1: Credentials & Secrets
**Always redacted** in all environments (production, development, testing)

Patterns matched (regex):
```
- API keys: api_key, apiKey, api-key
- Secrets: api_secret, apiSecret, secret_key
- Passwords: password, passwd, pwd
- Tokens: token, access_token, jwt, bearer_token
- Encryption: encryption_key, private_key
- Authentication: auth, authorization, credentials, passphrase
- Encrypted fields: any field containing "encrypted"
```

#### TIER 2: Business Data & PII
**Always redacted** to prevent leaking user identity and trading activity

Patterns matched:
```
- User identification: user_uid, user_id, account_id, customer_id
- Exchange identification: exchange, exchange_name, broker, platform
- Financial amounts: balance, equity, amount, value, price, total, pnl, profit, loss
- Trading activity: trade, position, order, quantity, size, volume, synced, count
- Personal information: name, email, phone, address, ssn, tax_id
```

### Redaction Examples

**Input (sensitive data):**
```typescript
logger.info('Sync completed', {
  user_uid: '550e8400-e29b-41d4-a716-446655440000',
  exchange: 'binance',
  total_equity: 10500.00,
  api_key: 'sk_live_abc123...',
  synced: true,
  count: 42
});
```

**Output (redacted):**
```json
{
  "timestamp": "2025-01-15T12:00:00.000Z",
  "level": "INFO",
  "context": "TradeSyncService",
  "message": "Sync completed",
  "metadata": {
    "user_uid": "[REDACTED]",      // TIER 2
    "exchange": "[REDACTED]",       // TIER 2
    "total_equity": "[REDACTED]",   // TIER 2
    "api_key": "[REDACTED]",        // TIER 1
    "synced": "[REDACTED]",         // TIER 2
    "count": "[REDACTED]"           // TIER 2
  },
  "enclave": true
}
```

**Safe logs (not redacted):**
```typescript
✅ logger.info('Sync job started');
✅ logger.info('Database connection established');
✅ logger.error('Validation failed', { error: err.message });
✅ logger.info('Enclave initialized successfully');
```

### Log Streaming Architecture

**Real-time log delivery** via Server-Sent Events (SSE) for development/monitoring:

```
┌─────────────────────────────────────────┐
│  Enclave Worker                         │
│  ┌────────────────────────────────────┐ │
│  │  SecureEnclaveLogger               │ │
│  │  - Filters sensitive data (TIER 1+2)│
│  │  - Writes to stdout/stderr         │ │
│  │  - Adds to circular buffer (500 entries)
│  └──────────────┬─────────────────────┘ │
│                 │                        │
│                 ▼                        │
│  ┌────────────────────────────────────┐ │
│  │  HTTP Log Server (port 3006)       │ │
│  │  - SSE endpoint: /logs/stream      │ │
│  │  - Polling fallback: /logs         │ │
│  │  - CORS: localhost only            │ │
│  └──────────────┬─────────────────────┘ │
└─────────────────┼───────────────────────┘
                  │
                  ▼ HTTP (local network only)
         ┌─────────────────┐
         │  Frontend       │
         │  - SSE client   │
         │  - Real-time UI │
         └─────────────────┘
```

**Security:**
- Logs are **already filtered** before buffering (TIER 1 + TIER 2)
- HTTP server binds to `127.0.0.1` (localhost only)
- Circular buffer prevents memory exhaustion (max 500 entries)
- Production: SSE disabled, logs to stdout only (Docker/systemd capture)

### Verification

**Auditors can verify:**
1. All log emissions pass through `filterSensitiveData()` (line 179)
2. TIER 1 and TIER 2 are ALWAYS active (no conditional logic)
3. `console.log` is NOT used in enclave code (enforced by ESLint)
4. SSE streaming only exposes pre-filtered logs (line 273)

---

## Memory Protection

Location: [src/services/memory-protection.service.ts](src/services/memory-protection.service.ts)

### Protection Mechanisms

#### 1. Core Dump Prevention

**Threat:** Core dumps can leak decrypted credentials to disk

**Mitigation:**
```typescript
// Disable core dumps at process level
process.setrlimit('core', { soft: 0, hard: 0 });

// Fallback: ulimit command
exec('ulimit -c 0');
```

**Verification:**
```bash
ulimit -c  # Should output: 0
```

#### 2. Ptrace Protection

**Threat:** Debuggers (gdb, strace) can attach and read process memory

**Mitigation:**
```
/proc/sys/kernel/yama/ptrace_scope = 2
```

**Levels:**
- `0`: No restrictions (INSECURE)
- `1`: Restricted to parent processes
- `2`: Admin-only ptrace (RECOMMENDED for production)
- `3`: No ptrace at all (maximum security)

**Check:**
```bash
cat /proc/sys/kernel/yama/ptrace_scope
# Production should be: 2 or 3
```

#### 3. Memory Locking (mlock)

**Threat:** Sensitive data paged to swap can be recovered from disk

**Mitigation:**
```typescript
// Check for mlock capability (requires CAP_IPC_LOCK)
const status = fs.readFileSync('/proc/self/status', 'utf8');
const vmLck = status.match(/VmLck:\s+(\d+)/);
```

**Production Setup:**
```bash
# Grant mlock capability
setcap cap_ipc_lock=+ep /usr/bin/node

# Or use systemd
[Service]
LockPersonality=yes
```

#### 4. Secure Buffer Wiping

**Threat:** Decrypted credentials may remain in memory after use

**Mitigation:**
```typescript
// Overwrite buffer with random data, then zeros
wipeBuffer(buffer: Buffer) {
  crypto.randomFillSync(buffer);  // Fill with random bytes
  buffer.fill(0);                 // Overwrite with zeros
}

// Wipe credentials after use
const apiKey = decrypt(encryptedApiKey);
// ... use apiKey ...
wipeString(apiKey);  // Securely erase from memory
```

#### 5. Cleanup on Shutdown

**Threat:** Secrets in environment variables may persist after process exit

**Mitigation:**
```typescript
// Register cleanup handlers
process.on('SIGTERM', cleanup);
process.on('SIGINT', cleanup);
process.on('beforeExit', cleanup);

function cleanup() {
  // Wipe JWT secrets
  if (process.env.JWT_SECRET) {
    wipeString(process.env.JWT_SECRET);
    delete process.env.JWT_SECRET;
  }
}
```

### Production Recommendations

```bash
# 1. Disable core dumps (systemd)
[Service]
LimitCORE=0

# 2. Enable ptrace protection
sudo sysctl kernel.yama.ptrace_scope=2

# 3. Enable ASLR (Address Space Layout Randomization)
sudo sysctl kernel.randomize_va_space=2

# 4. Enable seccomp (system call filtering)
[Service]
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# 5. Run in AMD SEV-SNP VM
# Memory encryption at hardware level
```

---

## Database Security

### Architecture

The enclave uses **PostgreSQL** with strict privilege separation and parameterized queries.

Location: [prisma/schema.prisma](prisma/schema.prisma)

### Privilege Separation

```sql
-- Enclave user (FULL access to sensitive tables)
CREATE USER enclave_user WITH PASSWORD 'strong_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON trades TO enclave_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON exchange_connections TO enclave_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON snapshot_data TO enclave_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON sync_rate_limit_logs TO enclave_user;

-- Gateway user (READ-ONLY access to aggregated data)
CREATE USER gateway_user WITH PASSWORD 'different_password';
GRANT SELECT ON snapshot_data TO gateway_user;
-- NO access to trades table
-- NO access to exchange_connections table
```

### Sensitive Tables

#### 1. exchange_connections (Credentials)

**Access:** Enclave only (enclave_user)

```sql
CREATE TABLE exchange_connections (
  id                   TEXT PRIMARY KEY,
  user_uid             TEXT NOT NULL,
  exchange             TEXT NOT NULL,
  encrypted_api_key    TEXT NOT NULL,  -- AES-256-GCM
  encrypted_api_secret TEXT NOT NULL,  -- AES-256-GCM
  encrypted_passphrase TEXT,           -- AES-256-GCM (optional)
  credentials_hash     TEXT,           -- SHA-256 (for deduplication)
  is_active            BOOLEAN DEFAULT TRUE,
  created_at           TIMESTAMP DEFAULT NOW(),
  updated_at           TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_uid, exchange)
);
```

**Security:**
- All credentials **AES-256-GCM encrypted** at rest
- Gateway has **NO access** (cannot read credentials)
- `credentials_hash` allows duplicate detection without decryption

#### 2. trades (Individual Trading Data)

**Access:** Enclave only (enclave_user)

```sql
CREATE TABLE trades (
  id                TEXT PRIMARY KEY,
  user_uid          TEXT NOT NULL,
  symbol            TEXT NOT NULL,
  type              TEXT NOT NULL,  -- 'buy' or 'sell'
  quantity          REAL NOT NULL,
  price             REAL NOT NULL,
  fees              REAL NOT NULL,
  timestamp         TIMESTAMP NOT NULL,
  exchange          TEXT,
  exchange_trade_id TEXT,
  status            TEXT DEFAULT 'pending',
  created_at        TIMESTAMP DEFAULT NOW(),
  INDEX(user_uid, symbol, timestamp),
  INDEX(exchange, timestamp)
);
```

**Security:**
- Individual trades **NEVER transmitted** outside enclave
- Gateway has **NO access** (cannot query trade history)
- Used ONLY for internal aggregation

#### 3. snapshot_data (Aggregated Output)

**Access:** Enclave (read/write) + Gateway (read-only)

```sql
CREATE TABLE snapshot_data (
  id                  TEXT PRIMARY KEY,
  user_uid            TEXT NOT NULL,
  timestamp           TIMESTAMP NOT NULL,  -- Daily 00:00 UTC
  exchange            TEXT NOT NULL,
  total_equity        REAL NOT NULL,       -- Total account value
  realized_balance    REAL NOT NULL,       -- Available cash
  unrealized_pnl      REAL NOT NULL,       -- Open positions P&L
  deposits            REAL DEFAULT 0,      -- Cash in
  withdrawals         REAL DEFAULT 0,      -- Cash out
  breakdown_by_market JSON,                -- Market breakdown (spot/swap/options)
  created_at          TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_uid, timestamp, exchange)
);
```

**Security:**
- Gateway can read (but NOT modify) snapshots
- NO individual trade data in this table
- Only daily aggregated equity

#### 4. sync_rate_limit_logs (Audit Trail)

**Access:** Enclave only (enclave_user)

```sql
CREATE TABLE sync_rate_limit_logs (
  id             TEXT PRIMARY KEY,
  user_uid       TEXT NOT NULL,
  exchange       TEXT NOT NULL,
  last_sync_time TIMESTAMP NOT NULL,
  sync_count     INTEGER DEFAULT 1,
  created_at     TIMESTAMP DEFAULT NOW(),
  updated_at     TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_uid, exchange),
  INDEX(last_sync_time)  -- For cleanup queries
);
```

**Security:**
- Proves snapshots are systematic (not cherry-picked)
- 23-hour cooldown enforced (see Rate Limiting)
- Gateway has NO access (prevents manipulation)

### SQL Injection Prevention

**All queries use Prisma ORM with parameterized statements.**

```typescript
// ❌ DANGEROUS: String concatenation
const result = await prisma.$queryRaw`
  SELECT * FROM trades WHERE user_uid = '${userUid}'
`;

// ✅ SAFE: Parameterized query (Prisma default)
const result = await prisma.trade.findMany({
  where: { userUid: userUid }  // Automatically parameterized
});
```

**Prisma generates safe SQL:**
```sql
-- Generated by Prisma (parameterized)
SELECT * FROM trades WHERE user_uid = $1;
-- Parameter: $1 = '550e8400-e29b-41d4-a716-446655440000'
```

**Verification:**
- Prisma Query Engine handles all parameterization
- No raw SQL queries in enclave code (auditable via grep)
- All repository methods use Prisma type-safe API

---

## Rate Limiting & Anti-Manipulation

### Purpose

**Prevent cherry-picking** by enforcing systematic daily snapshots.

Location: [src/services/sync-rate-limiter.service.ts](src/services/sync-rate-limiter.service.ts)

### Threat Model

**Threat:** User manipulates snapshot timing to hide losses

**Example Attack:**
```
Day 1: Portfolio up +10% → User triggers snapshot (shows profit)
Day 2: Portfolio down -15% → User SKIPS snapshot (hides loss)
Day 3: Portfolio up +5% → User triggers snapshot (shows profit)
```

**Result:** Performance appears better than reality (deceptive track record)

### Mitigation: 23-Hour Cooldown

**Enforcement:**
```typescript
// Minimum 23 hours between syncs for same user/exchange
const RATE_LIMIT_HOURS = 23;

async checkRateLimit(userUid, exchange) {
  const lastSync = await prisma.syncRateLimitLog.findUnique({
    where: { userUid_exchange: { userUid, exchange } }
  });

  if (!lastSync) {
    return { allowed: true };  // First sync
  }

  const hoursSinceLastSync =
    (Date.now() - lastSync.lastSyncTime.getTime()) / (1000 * 60 * 60);

  if (hoursSinceLastSync >= RATE_LIMIT_HOURS) {
    return { allowed: true };
  }

  // Rate limit exceeded
  const nextAllowedTime = new Date(
    lastSync.lastSyncTime.getTime() + (RATE_LIMIT_HOURS * 60 * 60 * 1000)
  );

  return {
    allowed: false,
    reason: `Rate limit exceeded. Next sync allowed at ${nextAllowedTime.toISOString()}`,
    nextAllowedTime
  };
}
```

### Audit Trail

**Every sync is recorded:**
```typescript
async recordSync(userUid, exchange) {
  await prisma.syncRateLimitLog.upsert({
    where: { userUid_exchange: { userUid, exchange } },
    update: {
      lastSyncTime: new Date(),
      syncCount: { increment: 1 }
    },
    create: {
      userUid,
      exchange,
      lastSyncTime: new Date(),
      syncCount: 1
    }
  });
}
```

**Database audit log:**
```
user_uid                              | exchange | last_sync_time       | sync_count
550e8400-e29b-41d4-a716-446655440000 | binance  | 2025-01-14 00:00:00 | 1
550e8400-e29b-41d4-a716-446655440000 | binance  | 2025-01-15 00:00:00 | 2
550e8400-e29b-41d4-a716-446655440000 | binance  | 2025-01-16 00:00:00 | 3
```

**Proof of systematic snapshots:**
- Auditors can verify timestamps are ~24 hours apart
- No gaps in snapshot sequence (except rate limit violations)
- Manual syncs blocked if cooldown not elapsed

### Autonomous Scheduler

**Daily snapshots triggered automatically** at 00:00 UTC:

Location: [src/services/daily-sync-scheduler.service.ts](src/services/daily-sync-scheduler.service.ts)

```typescript
// Cron: Every day at 00:00 UTC
cron.schedule('0 0 * * *', async () => {
  logger.info('[SCHEDULER] Daily sync started at 00:00 UTC');

  // Get all active users
  const users = await prisma.user.findMany();

  for (const user of users) {
    // Get active exchange connections
    const connections = await prisma.exchangeConnection.findMany({
      where: { userUid: user.uid, isActive: true }
    });

    for (const conn of connections) {
      // Check rate limit
      const rateCheck = await rateLimiter.checkRateLimit(user.uid, conn.exchange);

      if (!rateCheck.allowed) {
        logger.warn(`[SCHEDULER] Skipped ${conn.exchange} (rate limited)`);
        continue;
      }

      // Trigger snapshot creation
      await createSnapshot(user.uid, conn.exchange);

      // Record sync in audit log
      await rateLimiter.recordSync(user.uid, conn.exchange);
    }
  }
});
```

**Properties:**
- Runs inside hardware-attested enclave (cannot be manipulated)
- Systematic timing (00:00 UTC daily)
- Rate limiter prevents manual abuse
- Audit trail proves systematic execution

---

## Audit Trail

### What is Auditable?

1. **Source Code** (this repository)
   - All security mechanisms are open source
   - Reproducible builds verify deployed binary matches audited code

2. **Sync Rate Limit Logs** (database)
   - Timestamp of every snapshot creation
   - Proves systematic execution (not cherry-picked)

3. **Attestation Reports** (AMD SEV-SNP)
   - Binary hash (SHA-384)
   - Platform version
   - Cryptographic signature (ECDSA)

4. **Application Logs** (filtered)
   - Enclave initialization
   - Sync job execution
   - Errors and warnings
   - NO sensitive data (TIER 1 + TIER 2 redacted)

### Audit Tools

**For Independent Auditors:**

```bash
# 1. Verify source code matches deployed binary
git clone https://github.com/Jimmy7892/track-return-enclave.git
cd track-return-enclave
git checkout v1.0.0
npm ci
npm run build
sha256sum dist/**/*.js  # Compare with published hash

# 2. Check attestation report
curl -X POST https://enclave.trackrecord.com/api/v1/attestation
# Verify measurement matches build hash

# 3. Review rate limit logs (database query)
SELECT user_uid, exchange, last_sync_time, sync_count
FROM sync_rate_limit_logs
ORDER BY last_sync_time DESC;
# Verify ~24-hour intervals

# 4. Analyze logs for sensitive data leaks
grep -i "api.key\|password\|secret" /var/log/enclave/*.log
# Should return ZERO results (all redacted)
```

---

## Threat Model

### In-Scope Threats

#### 1. Compromised API Gateway

**Threat:** Attacker gains full control of the API Gateway service

**Impact without enclave:**
- Access to all individual trades
- Access to encrypted credentials (could attempt offline brute-force)

**Mitigation:**
- Gateway has NO access to `trades` table (PostgreSQL privileges)
- Gateway has NO access to `exchange_connections` table
- Gateway receives ONLY aggregated snapshots via gRPC
- Rate limiter audit logs prove systematic snapshots (not cherry-picked)

**Verification:**
```sql
-- Verify gateway_user cannot read trades
SELECT * FROM information_schema.table_privileges
WHERE grantee = 'gateway_user' AND table_name = 'trades';
-- Should return ZERO rows
```

#### 2. Compromised Hypervisor

**Threat:** Malicious cloud provider or attacker compromises VM hypervisor

**Impact without SEV-SNP:**
- Hypervisor can read all VM memory
- Can extract decrypted credentials
- Can steal individual trades

**Mitigation:**
- AMD SEV-SNP encrypts VM memory with hardware keys
- Hypervisor cannot decrypt memory (keys inaccessible)
- Attestation verifies memory encryption is active

**Verification:**
```bash
# Check SEV-SNP status
dmesg | grep -i sev
# Should show: AMD Secure Encrypted Virtualization (SEV) active

# Verify attestation
curl http://localhost:50051/health
# Should return: sevSnpEnabled: true
```

#### 3. Supply Chain Attack

**Threat:** Malicious code injected via compromised npm package

**Impact:**
- Attacker could exfiltrate credentials or trades
- Backdoor in dependencies

**Mitigation:**
- `package-lock.json` pins exact dependency versions and SHA-512 hashes
- Reproducible builds allow verification of deployed binary
- Regular `npm audit` checks for known vulnerabilities
- Minimal dependencies (49 total, 13 production)

**Verification:**
```bash
# Check for malicious dependencies
npm audit --production
# Should return: 0 vulnerabilities

# Verify integrity hashes
npm ci --integrity
# Fails if package-lock.json hashes don't match
```

#### 4. Malicious Insider

**Threat:** Infrastructure admin attempts to extract sensitive data

**Impact without attestation:**
- Admin could deploy modified enclave code
- Could add logging to exfiltrate credentials

**Mitigation:**
- SEV-SNP attestation verifies binary hash before Gateway connects
- Debug interfaces disabled in production build
- All enclave access logged (audit trail)
- Reproducible builds prove deployed binary matches audited source

**Verification:**
```typescript
// Gateway verifies attestation before connecting
const attestation = await sevSnpService.getAttestationReport();
if (!attestation.verified) {
  throw new Error('Enclave attestation failed - refusing to connect');
}
```

### Out-of-Scope Threats

- **Compromised AMD SEV-SNP firmware**: Requires hardware root of trust
- **Physical access to server**: Physical security is operational concern
- **Side-channel attacks**: Timing/power analysis out of scope
- **Denial of Service**: Availability separate from confidentiality

---

## Security Guarantees

### What the Enclave Guarantees

✅ **Credential Confidentiality**
- API keys decrypted ONLY in enclave memory (AMD SEV-SNP protected)
- NEVER logged (TIER 1 redaction)
- NEVER transmitted outside enclave
- Wiped from memory after use

✅ **Trade Privacy**
- Individual trades NEVER leave enclave boundary
- Only aggregated daily snapshots transmitted
- Gateway cannot access individual trade data (PostgreSQL privileges)

✅ **Code Integrity**
- Reproducible builds verify deployed binary matches audited source
- SEV-SNP attestation proves binary hash
- Auditors can independently verify build

✅ **Systematic Snapshots**
- Daily scheduler runs at 00:00 UTC (inside attested enclave)
- Rate limiter enforces 23-hour cooldown
- Audit trail proves systematic execution (not cherry-picked)

✅ **Hypervisor Isolation**
- AMD SEV-SNP memory encryption prevents hypervisor access
- Attestation verifies hardware protection is active

### What the Enclave Does NOT Guarantee

❌ **Timing Side-Channels**
- Cache timing attacks out of scope
- Constant-time crypto not implemented for performance

❌ **Physical Security**
- Physical access to server is operational concern
- Cold boot attacks mitigated by SEV-SNP (ephemeral keys)

❌ **Network Security**
- TLS/mTLS for gRPC is Gateway's responsibility
- Enclave trusts network layer

❌ **Availability**
- DoS attacks are separate from confidentiality
- Rate limiting prevents abuse but not targeted DoS

---

## Compliance

### Standards & Frameworks

#### GDPR (Article 32)
**Security of Processing**

✅ Pseudonymization: User UIDs (no email/name in enclave database)
✅ Encryption: AES-256-GCM for credentials at rest
✅ Confidentiality: AMD SEV-SNP hardware memory encryption
✅ Integrity: Authenticated encryption (GCM), attestation
✅ Availability: Database backups, rate limiting
✅ Resilience: Error handling, logging, monitoring

#### FIPS 140-2 Level 1
**Cryptographic Module**

✅ AES-256-GCM (NIST SP 800-38D approved)
✅ SHA-256/SHA-384 (NIST FIPS 180-4 approved)
✅ Node.js crypto module (OpenSSL-based, FIPS-capable)

**Production Recommendation:**
```bash
# Use FIPS-enabled Node.js build
export OPENSSL_FIPS=1
node --enable-fips dist/index.js
```

#### SOC 2 Type II
**Security Controls** (in progress)

✅ Access Controls: Database privilege separation
✅ Audit Logging: Sync rate limit logs, application logs
✅ Encryption: At-rest (AES-256-GCM), in-memory (SEV-SNP)
✅ Change Management: Git version control, reproducible builds
✅ Monitoring: Prometheus metrics, Grafana dashboards

### Certifications

| Certification | Status | Notes |
|---------------|--------|-------|
| **AMD SEV-SNP** | ✅ Production | Hardware attestation available |
| **FIPS 140-2** | ✅ Crypto compliant | OpenSSL FIPS mode recommended |
| **SOC 2 Type II** | 🔄 In progress | Audit controls implemented |
| **ISO 27001** | ⏳ Planned | Information security management |

---

## Security Contact

### Responsible Disclosure

If you discover a security vulnerability, please report it privately:

**Email:** security@trackrecord.com

**Response SLA:**
- Acknowledgment: 48 hours
- Initial assessment: 7 days
- Patch timeline: Based on severity (critical: 7 days, high: 30 days)

**Please do NOT:**
- Open public GitHub issues for security vulnerabilities
- Exploit vulnerabilities on production systems
- Publicly disclose before patch is available

### Security Researchers

We welcome responsible security research and will:
- Credit researchers in security advisories (unless anonymity requested)
- Provide detailed technical responses
- Consider bug bounty for critical findings (contact us for details)

---

## References

### AMD SEV-SNP
- [SEV-SNP Whitepaper](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)
- [SEV API Specification](https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf)

### Cryptography
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) (AES-GCM)
- [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) (SHA-2)
- [FIPS 140-2](https://csrc.nist.gov/publications/detail/fips/140/2/final) (Cryptographic Modules)

### Security Best Practices
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Reproducible Builds
- [Reproducible Builds Project](https://reproducible-builds.org/)
- [In-toto Framework](https://in-toto.io/)

---

**Document Version:** 1.0.0
**Last Updated:** 2025-11-26
**Maintained by:** Track Record Security Team
