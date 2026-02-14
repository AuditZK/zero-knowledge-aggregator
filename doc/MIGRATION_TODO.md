# Migration TODO — TypeScript to Go Feature Parity

> Generated: 2026-02-14
> Priority: P0 = Critical (security/data integrity), P1 = High (core features), P2 = Medium (enhancements), P3 = Low (polish)

---

## P0 — Critical (Security, Data Integrity)

- [ ] **[Security]** Deprecate plaintext `/api/v1/connection` endpoint — TS removed plaintext credential submission entirely. Go still accepts plaintext API keys via POST `/api/v1/connection`. This is a **security regression**. Options: (a) remove the endpoint entirely, (b) add a warning header and deprecation notice, (c) require E2E encryption in production mode.

- [ ] **[Security]** Add `GRPC_INSECURE` env var support — TS allows `GRPC_INSECURE=true` in dev mode to skip TLS on gRPC. Go gRPC server always creates insecure credentials. Should enforce TLS in production.

- [ ] **[Proto]** Update `enclave.proto` to match TypeScript proto — The Go proto is missing **20+ fields** in `SignedReportResponse`, 3 message types (`DailyReturnData`, `MonthlyReturnData`, `DrawdownPeriodData`), and the `SyncType` enum. This breaks gRPC interoperability. See FEATURE_PARITY_MATRIX.md Section 3 for full diff.

- [ ] **[Proto]** Fix `HealthCheckResponse` schema mismatch — TS uses `Status` enum (HEALTHY/UNHEALTHY), `enclave` bool, and `double uptime`. Go uses `string status`, `int64 uptime_seconds`, `bool database`, `int64 timestamp`. Decide which schema to standardize on.

- [ ] **[Encryption]** Verify ECIES interoperability — Both TS and Go use `"enclave-e2e-encryption"` as HKDF info string. However, TS sends ephemeral public key as PEM string, while Go handler expects raw hex bytes. Verify the Go `ConnectCredentials` handler correctly parses the same payload format that TS clients produce.

- [ ] **[Database]** Add `platform_hash` column to `users` table — TS has `platformHash` (SHA-256 of platformUserId, unique) for zero-knowledge user reconciliation. Go is missing this column. Create migration `008_add_platform_hash.sql`.

- [ ] **[Validation]** Add gRPC input validation — TS validates ALL gRPC requests with Zod schemas before processing. Go gRPC handlers (`internal/grpc/server.go`) do not call `internal/validation/` functions. Every gRPC handler MUST validate input.

---

## P1 — High (Core Features)

- [ ] **[Proto]** Add `DailyReturnData`, `MonthlyReturnData`, `DrawdownPeriodData` message types to proto — These are used by `GenerateSignedReport` response in TS and needed for chart rendering.

- [ ] **[Proto]** Add all missing fields to `SignedReportResponse` — Fields 16-82 (base_currency, benchmark, data_points, exchanges, annualized_return, volatility, sortino_ratio, calmar_ratio, risk metrics, benchmark metrics, drawdown data, chart data, attestation_id, enclave_mode).

- [ ] **[gRPC]** Update `GenerateSignedReport` handler to populate all proto fields — The Go `signing.SignedReport` struct already contains most data (DailyReturns, MonthlyReturns, RiskMetrics, etc.), but the gRPC response mapping is incomplete.

- [ ] **[Database]** Add `credentials_hash` column to `exchange_connections` — TS uses this for deduplication (prevents duplicate connections with same credentials). Create migration.

- [ ] **[Database]** Add `sync_interval_minutes` column to `exchange_connections` — TS stores per-connection sync interval. Go only has `sync_interval` on `users` table.

- [ ] **[Database]** Align `users.sync_interval` representation — TS uses `INT syncIntervalMinutes` (default 1440). Go uses `VARCHAR sync_interval` ('hourly'/'daily'). Consider migrating to INT for finer granularity.

- [ ] **[Connector]** Add `MockExchangeConnector` — TS has this for stress testing. Go should add `mock.go` implementing the `Connector` interface with configurable responses.

- [ ] **[Docker]** Add `snpguest` binary to Go Dockerfile — TS has a Rust build stage that compiles `snpguest@0.6.0` for AMD SEV-SNP attestation. Go Dockerfile is missing this. Critical for production deployment.

- [ ] **[Docker]** Add `-trimpath` flag to Dockerfile build command — Currently only in Makefile. Dockerfile uses `-ldflags="-w -s"` but missing `-trimpath`.

- [ ] **[Config]** Add `LOG_LEVEL` configuration — TS has `LOG_LEVEL` env var. Go Zap logger doesn't read this.

- [ ] **[Config]** Add `GRPC_INSECURE` configuration — TS uses this for dev-mode gRPC without TLS.

- [ ] **[Attestation]** Verify Go attestation response format — TS returns rich attestation object with `e2eEncryption`, `reportSigning`, `tlsBinding`, and `security` sections. Go returns a simpler format.

---

## P2 — Medium (Performance, Enhancements)

- [ ] **[Test]** Add connector tests — Port 4 TS connector tests (alpaca, ccxt, ibkr, tradestation) to Go.

- [ ] **[Test]** Add ECIES encryption tests — TS has round-trip, wrong-key tests for E2E encryption. Go has none.

- [ ] **[Test]** Add report signing/verification tests — TS has dedicated test files. Go has none.

- [ ] **[Test]** Add service tests — Port 6 TS service tests (daily-sync, equity-snapshot, metrics, performance, sync-rate-limiter, trade-sync).

- [ ] **[Test]** Add repository tests — Port 4 TS repository tests (dek, exchange-connection, sync-status, user).

- [ ] **[Test]** Add validation tests — Port TS grpc-schemas validation tests.

- [ ] **[Test]** Add server/handler tests — Port 2 TS server tests (enclave-server, rest-server).

- [ ] **[Test]** Add integration tests — Port 2 TS integration tests.

- [ ] **[Validation]** Enhance Go validation — TS Zod schemas have richer validation: max 100 char for user_uid, regex for exchange name, timestamp range validation (max 5 years), max 500 char for API keys. Go validation is more basic.

- [ ] **[Connector]** Verify `supportsFeature()` equivalent — TS connectors can report feature support (positions, trades, real_time, historical_data). Go has no equivalent.

- [ ] **[Service]** Verify data retention cleanup — TS has `DATA_RETENTION_DAYS` enforcement in daily sync. Verify Go implements this.

- [ ] **[Service]** Verify DEK rotation support — TS `KeyManagementService` has sophisticated DEK rotation with `rotatedAt` timestamps. Go implementation may be simpler.

- [ ] **[Logging]** Verify log sanitization — TS has dedicated `secure-enclave-logger.ts` that sanitizes sensitive data. Verify Go Zap logger does the same.

- [ ] **[Proxy]** Verify per-exchange proxy scoping — TS only routes specific exchanges through proxy (Binance only by default). Go has `PROXY_EXCHANGES` config var but need to verify implementation matches.

- [ ] **[Docker]** Add `read_only: true` to Dockerfile — TS docker-compose has read-only filesystem. Go only has it in docker-compose, not enforced at image level.

- [ ] **[Docker]** Consider adding `tini` init system — TS uses tini for signal handling. Go handles signals natively but tini prevents zombie processes.

---

## P3 — Low (Refactoring, Documentation, Polish)

- [ ] **[Config]** Evaluate `JWT_SECRET` requirement — TS requires JWT_SECRET at startup. Go doesn't have it. Determine if this is needed for the Go implementation.

- [ ] **[Config]** Add `DB_SSL`, `DB_MAX_CONNECTIONS`, `DB_IDLE_TIMEOUT_MS` config options — TS has these; Go uses pgx defaults.

- [ ] **[Config]** Add `ENABLE_DAILY_SYNC`, `ENABLE_ENCLAVE_LOG_STREAMING` toggles — TS has these feature flags.

- [ ] **[Config]** Standardize env var names — TS uses `NODE_ENV`, `ENCLAVE_PORT`, `HTTP_LOG_PORT`. Go uses `ENV`, `GRPC_PORT`, `LOG_STREAM_PORT`. Document the mapping.

- [ ] **[Config]** Align default REST port — TS defaults to 3050, Go defaults to 8080. Document or standardize.

- [ ] **[Docs]** Create `.env.example` — Go should have a documented `.env.example` with all config vars and their descriptions.

- [ ] **[Docker]** Align PostgreSQL version — TS uses 15-alpine, Go uses 16-alpine. Minor but should be consistent.

- [ ] **[Connector]** Add base connector type/helper — TS has `BaseExchangeConnector`, `CryptoExchangeConnector`, `RestBrokerConnector` base classes that provide shared HTTP client config, error handling, and market breakdown logic. Go connectors may duplicate this logic.

- [ ] **[Code]** Add `hexDecode` to a shared utility — Go handler has inline `hexDecode` function. Move to a shared package.

- [ ] **[Metrics]** Verify Prometheus metric names match between TS and Go — TS has `enclave_attestation_success_total`, `enclave_attestation_failure_total`, etc.

---

## Summary

| Priority | Count | Status |
|----------|-------|--------|
| P0 (Critical) | 7 | 🚨 Must fix before production |
| P1 (High) | 12 | ⚠️ Required for feature parity |
| P2 (Medium) | 16 | 📋 Quality and completeness |
| P3 (Low) | 10 | 🔧 Polish and documentation |
| **Total** | **45** | |
