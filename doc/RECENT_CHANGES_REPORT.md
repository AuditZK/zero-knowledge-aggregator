# Recent TypeScript Changes — Migration Status in Go

> Generated: 2026-02-14
> Source: `git log --oneline -30` from `D:\Dev\zero-knowledge-aggregator`

---

## Commit History

| # | Commit | Type | Description | Status in Go | Priority |
|---|--------|------|-------------|--------------|----------|
| 1 | `8f4bf37` | Fix | Fallback to `ENCRYPTION_KEY` env var in dev mode | ✅ Ported | — |
| 2 | `b628335` | Fix | Respect `GRPC_INSECURE` env var in dev mode | ❌ Missing | P1 |
| 3 | `03fc178` | Fix | Fix TS strict type errors in MockExchangeConnector | N/A | — |
| 4 | `26272ac` | Feature | Add `MockExchangeConnector` for stress testing | ❌ Missing | P1 |
| 5 | `e34ba43` | Feature | Add `Dockerfile.dev` for local dev without SEV-SNP | ❌ Missing | P3 |
| 6 | `c730dd0` | Feature | Track deposits/withdrawals in snapshots | ✅ Ported | — |
| 7 | `422977c` | Fix | Sum equity across all exchanges for global portfolio | ⚠️ Verify | P2 |
| 8 | `0607693` | Security | Update axios to 1.13.5 (DoS via `__proto__` in mergeConfig) | N/A (Go uses net/http) | — |
| 9 | `49a008c` | Feature | Add `platformHash` field for user identification | ❌ Missing | P0 |
| 10 | `921f9b3` | Security | Remove IBKR financial data leak from logs, scope proxy to Binance only | ⚠️ Verify | P0 |
| 11 | `5037390` | Fix | Use 24h lookback for trades instead of startOfDay | ⚠️ Verify | P2 |
| 12 | `17a2429` | Feature | Load `EXCHANGE_HTTP_PROXY` from GCP metadata | ❌ Missing | P3 |
| 13 | `1567ba7` | Feature | Add `EXCHANGE_HTTP_PROXY` env var to docker-compose | ✅ Ported | — |
| 14 | `d726dca` | Feature | Add HTTP proxy support for geo-restricted exchanges | ✅ Ported | — |
| 15 | `e1d43b1` | Fix | Handle existing index in constraint check (migration) | ✅ Ported (IF NOT EXISTS) | — |
| 16 | `72375fa` | Fix | Fix strict null check on Lighter accounts array | ⚠️ Verify | P2 |
| 17 | `bae742b` | Feature | Add Lighter DEX connector, fix extractSwapEquity, update CCXT | ✅ Ported | — |
| 18 | `89eec16` | Fix | Add startup migration to update unique constraints (multi-account) | ✅ Ported (migration 004) | — |
| 19 | `c21606e` | Revert | Restore anti-cherry-picking check after emergency | ⚠️ Verify | P2 |
| 20 | `eb4037a` | Fix | Avoid unreachable code in bypass for emergency snapshot | N/A (TS-specific) | — |
| 21 | `658ccb4` | Temp | Bypass manual sync check for emergency snapshot | N/A (reverted) | — |
| 22 | `96d934b` | Temp | Disable manual sync check for emergency snapshot | N/A (reverted) | — |
| 23 | `069310b` | Fix | Add missing label to `upsertSyncStatus` calls in trade-sync | ⚠️ Verify | P2 |
| 24 | `bb5449e` | Fix | Improve P2002 error message to include label | ⚠️ Verify | P3 |
| 25 | `a63925f` | Feature | Allow multiple connections per exchange (multi-account) | ✅ Ported (migration 004) | — |
| 26 | `d0e0952` | Refactor | Migrate cTrader from REST to WebSocket JSON API | ⚠️ Verify | P1 |
| 27 | `8346cb3` | Fix | Add numeric validation for equity values | ⚠️ Verify | P2 |
| 28 | `7360b38` | Fix | Correct field name mismatch and extract trades/fees from breakdown | ⚠️ Verify | P2 |
| 29 | `8753ac7` | Feature | Add 5-second cache for attestation reports | ✅ Ported | — |
| 30 | `f148423` | Fix | MEXC: extract real equity from derivatives balance | ⚠️ Verify | P2 |

---

## Summary by Status

| Status | Count | Details |
|--------|-------|---------|
| ✅ Ported | 10 | Core features migrated |
| ❌ Missing | 4 | GRPC_INSECURE, MockExchangeConnector, platformHash, Dockerfile.dev |
| ⚠️ Verify | 11 | Need manual verification in Go implementation |
| N/A | 5 | TS-specific (type errors, reverted changes, axios CVE) |

---

## Critical Missing Items (from recent commits)

### 1. `platformHash` — Commit `49a008c` (P0)
Added `platformHash` field to users table for zero-knowledge user identification. This is a SHA-256 hash of the platform user ID, enabling reconciliation without exposing the real ID. **Go is missing this column and the hashing logic.**

### 2. IBKR log leak fix — Commit `921f9b3` (P0)
Security fix that removes IBKR financial data from logs and scopes the HTTP proxy to Binance only. **Need to verify Go IBKR connector doesn't leak financial data in Zap logs.**

### 3. cTrader WebSocket migration — Commit `d0e0952` (P1)
TS migrated cTrader from REST API to WebSocket JSON API. **Need to verify Go cTrader connector uses the correct API type.**

### 4. `GRPC_INSECURE` support — Commit `b628335` (P1)
Allows dev mode without TLS on gRPC. **Go needs this for easier local development.**

### 5. `MockExchangeConnector` — Commit `26272ac` (P1)
Stress testing connector with configurable responses. **Go should add this for testing.**

---

## Items Requiring Verification

The following items are marked ⚠️ and need manual code comparison:

1. **Global portfolio equity summation** (`422977c`) — Verify Go metrics service sums equity across all exchanges correctly
2. **24h trade lookback** (`5037390`) — Verify Go uses 24-hour lookback window instead of startOfDay
3. **Lighter null check** (`72375fa`) — Verify Go Lighter connector handles nil/empty accounts
4. **Anti-cherry-picking check** (`c21606e`) — Verify Go daily sync prevents manual sync timing manipulation
5. **Label in upsertSyncStatus** (`069310b`) — Verify Go includes label when upserting sync status
6. **P2002 error handling** (`bb5449e`) — Verify Go provides meaningful errors for unique constraint violations
7. **cTrader API type** (`d0e0952`) — Verify Go cTrader connector uses WebSocket JSON API
8. **Numeric equity validation** (`8346cb3`) — Verify Go validates equity values are numeric and reasonable
9. **Breakdown field names** (`7360b38`) — Verify Go uses correct field names for market breakdown
10. **MEXC equity extraction** (`f148423`) — Verify Go handles MEXC derivatives balance correctly (via CCXT/OKX path)
