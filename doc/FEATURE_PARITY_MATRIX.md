# Feature Parity Matrix — TypeScript vs. Go

> Generated: 2026-02-14
> TypeScript repo: `D:\Dev\zero-knowledge-aggregator`
> Go repo: `d:\Dev\zero-knowledge-aggregator-go`

---

## 1. Exchange Connectors

| Exchange | TypeScript | Go | Notes |
|----------|-----------|-----|-------|
| Binance | ✅ CcxtExchangeConnector | ✅ binance.go | TS uses CCXT library; Go has native impl |
| Bybit | ✅ CcxtExchangeConnector | ✅ bybit.go | TS uses CCXT library; Go has native impl |
| OKX | ✅ CcxtExchangeConnector | ✅ okx.go | TS uses CCXT library; Go has native impl |
| IBKR | ✅ IbkrFlexConnector | ✅ ibkr.go | Flex API in both |
| Alpaca | ✅ AlpacaConnector | ✅ alpaca.go | TS uses @alpacahq/alpaca-trade-api SDK |
| TradeStation | ✅ TradeStationConnector | ✅ tradestation.go | OAuth flow in both |
| Hyperliquid | ✅ HyperliquidConnector | ✅ hyperliquid.go | Read-only DEX, wallet address only |
| Lighter | ✅ LighterConnector | ✅ lighter.go | DEX integration |
| cTrader | ✅ CTraderConnector | ✅ ctrader.go | WebSocket JSON API (TS migrated from REST) |
| **MockExchange** | ✅ MockExchangeConnector | ❌ Missing | **TODO**: Stress testing connector |

### Connector Interface Differences

| Feature | TypeScript (`IExchangeConnector`) | Go (`Connector`) | Gap |
|---------|----------------------------------|-------------------|-----|
| GetBalance | ✅ `getBalance(): Promise<BalanceData>` | ✅ `GetBalance(ctx) (*Balance, error)` | — |
| GetPositions | ✅ `getCurrentPositions(): Promise<PositionData[]>` | ✅ `GetPositions(ctx) ([]*Position, error)` | — |
| GetTrades | ✅ `getTrades(start, end): Promise<TradeData[]>` | ✅ `GetTrades(ctx, start, end) ([]*Trade, error)` | — |
| TestConnection | ✅ `testConnection(): Promise<boolean>` | ✅ `TestConnection(ctx) error` | — |
| ExchangeName | ✅ `getExchangeName(): string` | ✅ `Exchange() string` | — |
| SupportsFeature | ✅ `supportsFeature(feature)` | ❌ Missing | Go lacks feature detection |
| Base classes | ✅ `BaseExchangeConnector`, `CryptoExchangeConnector`, `RestBrokerConnector` | ❌ No base types | Go uses flat interface |
| Market breakdown | ✅ Built-in via `CryptoExchangeConnector` | ⚠️ MarketType field on Trade/Position | Need to verify aggregation |
| Proxy support | ✅ Via `EXCHANGE_HTTP_PROXY` per exchange | ✅ Via `EXCHANGE_HTTP_PROXY` | Verify per-exchange scoping |

---

## 2. REST API Endpoints

| Endpoint | Method | TypeScript | Go | Notes |
|----------|--------|-----------|-----|-------|
| `/health` | GET | ✅ | ✅ | Response format differs slightly |
| `/api/v1/tls/fingerprint` | GET | ✅ | ✅ | — |
| `/api/v1/attestation` | GET | ✅ | ✅ | TS returns richer response (E2E key, report signing key) |
| `/api/v1/credentials/connect` | POST | ✅ (E2E only) | ✅ | Rate limited: 5/15min |
| `/api/v1/connection` | POST | ❌ **Removed** | ✅ (plaintext) | **SECURITY**: TS removed plaintext; Go still has it |
| `/api/v1/sync` | POST | ❌ (gRPC only) | ✅ | TS handles sync only via gRPC |
| `/api/v1/metrics` | GET | ❌ (gRPC only) | ✅ | TS handles metrics only via gRPC |
| `/api/v1/snapshots` | GET | ❌ (gRPC only) | ✅ | TS handles snapshots only via gRPC |
| `/api/v1/report` | POST | ❌ (gRPC only) | ✅ | TS handles reports only via gRPC |
| `/api/v1/verify` | POST | ❌ (gRPC only) | ✅ | TS handles verify only via gRPC |

### Key Difference
The Go version exposes sync/metrics/snapshots/report/verify via **both** REST and gRPC, while TypeScript exposes them **only via gRPC**. The Go REST endpoints are an intentional addition for easier client integration.

**SECURITY ISSUE**: `/api/v1/connection` in Go accepts plaintext credentials. TypeScript **removed** this endpoint and only accepts E2E encrypted credentials via `/api/v1/credentials/connect`. The Go version SHOULD deprecate plaintext.

---

## 3. gRPC Methods

| Method | TypeScript | Go | Notes |
|--------|-----------|-----|-------|
| HealthCheck | ✅ | ✅ | Response schema differs (see below) |
| ProcessSyncJob | ✅ | ✅ | TS has deprecated `SyncType` enum |
| GetAggregatedMetrics | ✅ | ✅ | — |
| GetSnapshotTimeSeries | ✅ | ✅ | — |
| CreateUserConnection | ✅ | ✅ | — |
| GetPerformanceMetrics | ✅ | ✅ | — |
| GenerateSignedReport | ✅ | ✅ | **CRITICAL**: Response schemas differ significantly |
| VerifyReportSignature | ✅ | ✅ | — |

### Proto File Differences (CRITICAL)

| Field/Message | TypeScript Proto | Go Proto | Gap |
|--------------|-----------------|----------|-----|
| `SyncJobRequest.SyncType` enum | ✅ (deprecated) | ❌ Missing | Backwards compat issue |
| `HealthCheckResponse.Status` enum | ✅ (HEALTHY/UNHEALTHY) | ❌ Uses `string status` | Schema mismatch |
| `HealthCheckResponse.enclave` | ✅ `bool enclave` | ❌ Missing | Missing field |
| `HealthCheckResponse.uptime` | ✅ `double uptime` | ✅ `int64 uptime_seconds` | Type mismatch |
| `HealthCheckResponse.database` | ❌ | ✅ `bool database` | Go extra field |
| `HealthCheckResponse.timestamp` | ❌ | ✅ `int64 timestamp` | Go extra field |
| `SignedReportResponse.base_currency` | ✅ field 16 | ❌ Missing | |
| `SignedReportResponse.benchmark` | ✅ field 17 | ❌ Missing | |
| `SignedReportResponse.data_points` | ✅ field 18 | ❌ Missing | |
| `SignedReportResponse.exchanges` | ✅ field 19 (repeated string) | ❌ Missing | |
| `SignedReportResponse.annualized_return` | ✅ field 21 | ❌ Missing | |
| `SignedReportResponse.volatility` | ✅ field 22 | ❌ Missing | |
| `SignedReportResponse.sortino_ratio` | ✅ field 24 | ❌ Missing | |
| `SignedReportResponse.calmar_ratio` | ✅ field 26 | ❌ Missing | |
| `SignedReportResponse` risk metrics (30-34) | ✅ var_95, var_99, expected_shortfall, skewness, kurtosis | ❌ Missing | |
| `SignedReportResponse` benchmark metrics (40-44) | ✅ alpha, beta, information_ratio, tracking_error, correlation | ❌ Missing | |
| `SignedReportResponse` drawdown data (50-52) | ✅ max_drawdown_duration, current_drawdown, drawdown_periods | ❌ Missing | |
| `SignedReportResponse` chart data (60-61) | ✅ daily_returns, monthly_returns | ❌ Missing | |
| `SignedReportResponse.attestation_id` | ✅ field 81 | ❌ Missing | |
| `SignedReportResponse.enclave_mode` | ✅ field 82 | ❌ Missing | |
| `DailyReturnData` message | ✅ | ❌ Missing | |
| `MonthlyReturnData` message | ✅ | ❌ Missing | |
| `DrawdownPeriodData` message | ✅ | ❌ Missing | |

**NOTE**: Go's `signing.SignedReport` struct contains many of these fields internally (DailyReturns, MonthlyReturns, RiskMetrics, DrawdownData, BenchmarkMetrics), but the **proto definition** doesn't expose them. The Go gRPC handler would need proto updates to transmit this data.

---

## 4. Database Schema

| Table | TypeScript | Go | Differences |
|-------|-----------|-----|-------------|
| `users` | ✅ | ✅ | See details below |
| `exchange_connections` | ✅ | ✅ | See details below |
| `snapshot_data` | ✅ | ✅ (migration 002) | — |
| `data_encryption_keys` | ✅ | ✅ (migration 003) | Column differences |
| `sync_statuses` | ✅ | ✅ (migration 005) | — |
| `signed_reports` | ✅ | ✅ (migration 006) | — |
| `sync_rate_limit_logs` | ✅ | ✅ (migration 007) | — |
| `migrations` (tracking) | ✅ (Prisma model) | ❌ Missing | Go uses migration files only |

### `users` Table Differences

| Column | TypeScript | Go | Gap |
|--------|-----------|-----|-----|
| `id` | CUID (string) | UUID | Type difference |
| `uid` | ✅ | ✅ | — |
| `platformHash` | ✅ (SHA-256, unique) | ❌ **Missing** | **TODO**: Add platform_hash column |
| `syncIntervalMinutes` | ✅ (INT, default 1440) | `sync_interval` VARCHAR ('hourly'/'daily') | Different representation |
| `created_at` | ✅ | ✅ | — |
| `updated_at` | ✅ | ✅ | — |

### `exchange_connections` Table Differences

| Column | TypeScript | Go | Gap |
|--------|-----------|-----|-----|
| Encryption storage | Single hex string per field (iv+tag+ciphertext) | Separate columns (encrypted, iv, auth_tag) | Different approach, both valid |
| `credentialsHash` | ✅ (SHA-256 hash for dedup) | ❌ **Missing** | **TODO**: Add credentials_hash |
| `syncIntervalMinutes` | ✅ (per-connection) | ❌ Missing | On users table in Go but not connections |
| `label` | ✅ (required) | ✅ | — |

### `data_encryption_keys` Table Differences

| Column | TypeScript | Go |
|--------|-----------|-----|
| `encryptedDEK` | ✅ | ✅ `encrypted_dek` |
| `iv` | ✅ | ✅ `nonce` |
| `authTag` | ✅ | ❌ (combined in ciphertext) |
| `keyVersion` | ✅ | ❌ Missing |
| `masterKeyId` | ✅ | ✅ `master_key_id` |
| `isActive` | ✅ | ✅ `is_active` |
| `rotatedAt` | ✅ | ❌ Missing |

---

## 5. Encryption & Cryptography

| Component | TypeScript | Go | Algorithm Match | Notes |
|-----------|-----------|-----|----------------|-------|
| Credential encryption (AES-256-GCM) | ✅ Node crypto | ✅ crypto/aes + cipher.NewGCM | ✅ | Different storage format (single hex vs separate fields) |
| ECIES (E2E encryption) | ✅ ECDH P-256 + HKDF + AES-256-GCM | ✅ ecdh.P256 + HKDF + AES-256-GCM | ✅ | Same HKDF info string: "enclave-e2e-encryption" |
| Report signing | ✅ **ECDSA P-256** with SHA-256 | ✅ **Ed25519** | **INTENTIONAL CHANGE** | Go uses Ed25519 per AGENTS.md |
| TLS certificates | ✅ ECDSA P-256 | ✅ ECDSA P-256 | ✅ | Both generate self-signed at startup |
| Key derivation (HKDF) | ✅ crypto.hkdfSync | ✅ golang.org/x/crypto/hkdf | ✅ | — |
| HMAC-SHA256 (exchange signing) | ✅ crypto.createHmac | ✅ crypto/hmac | ✅ | Used in connector implementations |
| Attestation binding (SHA-256) | ✅ crypto.createHash | ✅ crypto/sha256 | ✅ | — |
| DEK key management | ✅ KeyManagementService | ⚠️ Simpler in Go | Partial | TS has more sophisticated DEK rotation |
| Key zeroing | ⚠️ Not verified | ⚠️ ECIESService.Cleanup() | Partial | Only ECIES key wiped in Go |

### Signing Algorithm Divergence (INTENTIONAL)
- TypeScript: ECDSA P-256 (secp256r1) with SHA-256 — `createSign('SHA256')`
- Go: Ed25519 — `ed25519.Sign()`
- **Justification**: AGENTS.md specifies Ed25519 for report signing. This is a deliberate upgrade.
- **Impact**: Reports signed by TS cannot be verified by Go and vice versa. This is acceptable as they are separate instances.

---

## 6. Configuration Variables

| Variable | TypeScript | Go | Default (TS → Go) | Notes |
|----------|-----------|-----|-------------------|-------|
| `ENV` / `NODE_ENV` | ✅ `NODE_ENV` | ✅ `ENV` | development | Different var name |
| `DATABASE_URL` | ✅ | ✅ | — | — |
| `ENCRYPTION_KEY` | ✅ | ✅ | random in dev | — |
| `GRPC_PORT` / `ENCLAVE_PORT` | ✅ `ENCLAVE_PORT` (50051) | ✅ `GRPC_PORT` (50051) | Different name |
| `REST_PORT` | ✅ (3050) | ✅ (8080) | **Different defaults** | |
| `LOG_STREAM_PORT` / `HTTP_LOG_PORT` | ✅ `HTTP_LOG_PORT` (50052) | ✅ `LOG_STREAM_PORT` (50052) | Different name |
| `METRICS_PORT` | ✅ (9090) | ✅ (9090) | — | — |
| `METRICS_ENABLED` | ✅ | ✅ | true | — |
| `CORS_ORIGIN` | ✅ | ✅ | `http://localhost:3000` (TS) / `""` (Go) | — |
| `EXCHANGE_HTTP_PROXY` | ✅ | ✅ | — | — |
| `PROXY_EXCHANGES` | ❌ (hardcoded) | ✅ | "binance" | Go makes it configurable |
| `BENCHMARK_SERVICE_URL` | ✅ | ✅ | — | — |
| `DATA_RETENTION_DAYS` | ✅ (30) | ✅ (30) | — | — |
| `LOG_STREAM_API_KEY` | ❌ | ✅ | — | Go addition |
| `JWT_SECRET` | ✅ (required) | ❌ **Missing** | — | **TODO**: Evaluate if needed |
| `GRPC_INSECURE` | ✅ | ❌ | — | Dev TLS bypass |
| `LOG_LEVEL` | ✅ | ❌ **Missing** | info | **TODO**: Add log level config |
| `DB_SSL` | ✅ | ❌ | — | TS has explicit SSL toggle |
| `DB_MAX_CONNECTIONS` | ✅ (50) | ❌ | — | Go uses pgx defaults |
| `ENABLE_DAILY_SYNC` | ✅ | ❌ | — | TS has toggle |
| `ENABLE_ENCLAVE_LOG_STREAMING` | ✅ | ❌ | — | TS has toggle |

---

## 7. Tests

| Category | TypeScript Count | Go Count | Gap |
|----------|-----------------|----------|-----|
| **Connector tests** | 4 (alpaca, ccxt, ibkr, tradestation) | 0 | ❌ All missing |
| **External service tests** | 3 (alpaca-api, ibkr-flex, tradestation-api) | 0 | ❌ All missing |
| **Encryption tests** | 3 (encryption, e2e-encryption, key-derivation) | 1 (aes_test.go: 3 tests) | ❌ ECIES, HKDF tests missing |
| **Key management tests** | 1 (key-management) | 0 | ❌ Missing |
| **Report tests** | 2 (report-generator, report-signing) | 0 | ❌ Missing |
| **Service tests** | 6 (daily-sync, equity-snapshot, metrics, performance, sync-rate-limiter, trade-sync) | 0 | ❌ All missing |
| **Repository tests** | 4 (dek, exchange-connection, sync-status, user) | 0 | ❌ All missing |
| **Validation tests** | 1 (grpc-schemas) | 0 | ❌ Missing |
| **Server tests** | 2 (enclave-server, rest-server) | 0 | ❌ All missing |
| **Integration tests** | 2 (enclave-server, rest-server integration) | 0 | ❌ All missing |
| **Utility tests** | 2 (secure-enclave-logger, time-utils) | 0 | ❌ Missing |
| **Config tests** | 1 (config/index) | 0 | ❌ Missing |
| **Health check tests** | 1 | 0 | ❌ Missing |
| **Other service tests** | 2 (memory-protection, tls-key-generator, sev-snp-attestation) | 0 | ❌ Missing |
| **TOTALS** | **35 test files** | **1 test file** | **34 missing** |

---

## 8. Dependencies

| Capability | TypeScript | Go | Notes |
|------------|-----------|-----|-------|
| PostgreSQL | `@prisma/client` (Prisma ORM) | `pgx/v5` (raw SQL) | Intentional: Go uses raw queries |
| Logging | Secure enclave logger (custom) | `go.uber.org/zap` | — |
| gRPC | `@grpc/grpc-js` + `@grpc/proto-loader` | `google.golang.org/grpc` | — |
| UUID | TS built-in / CUID | `github.com/google/uuid` | — |
| Crypto | Node.js `crypto` module | `golang.org/x/crypto` + stdlib | — |
| HTTP client | `axios` | `net/http` | — |
| Validation | `zod` | Custom `internal/validation` | Go validation is simpler |
| Exchange SDK | `ccxt` (multi-exchange) | Native per-exchange | Intentional |
| Alpaca SDK | `@alpacahq/alpaca-trade-api` | Native HTTP | — |
| XML parsing | `xml2js` | ❌ Missing | Needed for IBKR Flex XML |
| Cron scheduling | `node-cron` | Custom ticker | — |
| DI container | `tsyringe` (reflect-metadata) | Constructor injection | Intentional |
| Rate limiting | `express-rate-limit` | Custom `internal/server/ratelimit.go` | — |
| Web framework | `express` v5 | `net/http` (stdlib) | Intentional |

---

## 9. Docker & Infrastructure

| Component | TypeScript | Go | Notes |
|-----------|-----------|-----|-------|
| Build stages | 3 (Rust snpguest + Node builder + runtime) | 2 (Go builder + Alpine runtime) | Go missing snpguest |
| Base image (runtime) | `node:20-alpine` | `alpine:3.20` | — |
| Non-root user | `enclave` (commented out for SEV-SNP) | `enclave` (active) | TS needs root for `/dev/sev-guest` |
| Read-only filesystem | ✅ | ❌ Not in Dockerfile | Only in docker-compose |
| HEALTHCHECK | ✅ (Node HTTP check) | ✅ (wget) | — |
| snpguest binary | ✅ (Rust-compiled) | ❌ **Missing** | **CRITICAL** for production attestation |
| Init system (tini) | ✅ (ENTRYPOINT tini) | ❌ Missing | Go handles signals natively |
| PostgreSQL version | 15-alpine (docker-compose) | 16-alpine | Minor version diff |
| Exposed ports | 50051, 3050, 50052, 9090 | 8080, 50051, 50052, 9090 | Different REST port |
| VCEK cert cache dir | ❌ | ✅ `/var/cache/enclave/certs` | Go addition |
| `-trimpath` flag | N/A | ✅ (Makefile, not in Dockerfile) | **TODO**: Add -trimpath to Dockerfile |

---

## 10. Operational Tooling

| Feature | TypeScript | Go | Notes |
|---------|-----------|-----|-------|
| Prometheus metrics | ✅ `services/metrics.service.ts` | ✅ `internal/metrics/` | Need to verify metric names match |
| Health check endpoint | ✅ (both REST and gRPC) | ✅ (both REST and gRPC) | — |
| Graceful shutdown | ✅ (via NestJS/tini) | ✅ (SIGTERM/SIGINT + context) | — |
| SSE log streaming | ✅ `http-log-server.ts` | ✅ `internal/logstream/` | — |
| Memory locking (mlockall) | ✅ `memory-protection.service.ts` | ✅ `internal/security/` | — |
| Attestation caching | ✅ (5s cache) | ✅ (5s cache + 7-day VCEK) | — |
| Rate limiting | ✅ `express-rate-limit` | ✅ `internal/server/ratelimit.go` | — |
| CORS middleware | ✅ (Express config) | ✅ `internal/server/cors.go` | — |
| Connector caching | ✅ `universal-connector-cache.service.ts` | ✅ `internal/cache/` | — |
| Data retention cleanup | ✅ (in daily sync) | ⚠️ Need to verify | May be missing |
| Benchmark service client | ✅ | ✅ `internal/service/benchmark.go` | — |
| Startup migrations | ✅ `pg-startup-migrations.ts` + Prisma | ✅ (file-based migrations) | — |
