# Plan de Conversion Node.js/TypeScript → Go

**Projet**: Zero-Knowledge Aggregator (Enclave AMD SEV-SNP)
**État actuel**: ~7,100 lignes TypeScript (51 fichiers)
**Objectif**: Réduction RAM (5-10x), CPU (2-4x), Build (<3s)

---

## 1. Architecture Actuelle

### Structure du projet
```
src/
├── index.ts                      # Entry point (130 LOC)
├── enclave-server.ts             # gRPC server (929 LOC)
├── enclave-worker.ts             # Business logic orchestrator
├── rest-server.ts                # HTTPS REST API (333 LOC)
├── http-log-server.ts            # SSE log streaming
├── config/
│   ├── enclave-container.ts      # DI container (tsyringe)
│   └── index.ts                  # Config loader (GCP metadata)
├── services/                     # 15 services
│   ├── encryption-service.ts             # AES-256-GCM
│   ├── sev-snp-attestation.service.ts    # Hardware attestation
│   ├── equity-snapshot-aggregator.ts     # Daily aggregation
│   ├── trade-sync-service.ts             # Exchange sync orchestrator
│   ├── daily-sync-scheduler.service.ts   # Cron scheduler
│   └── ...
├── connectors/                   # 4 exchange connectors
│   ├── CcxtExchangeConnector.ts  # CCXT wrapper (crypto)
│   ├── AlpacaConnector.ts        # Alpaca API
│   ├── IbkrFlexConnector.ts      # IBKR Flex queries
│   └── TradeStationConnector.ts  # TradeStation
├── core/
│   ├── repositories/             # 6 Prisma repositories
│   └── services/                 # Database migrations, cache
├── external/                     # API wrappers
├── types/                        # TypeScript interfaces
├── validation/                   # Zod schemas
└── utils/                        # Logger, time utils
```

### Dépendances Critiques

| Dépendance | Usage | Taille runtime | Équivalent Go |
|------------|-------|----------------|---------------|
| **ccxt** v4.5.22 | 200+ exchanges | ~50 MB/instance | ❌ Aucun (problème majeur) |
| **@grpc/grpc-js** | gRPC server | ~10 MB | ✅ google.golang.org/grpc |
| **@prisma/client** | PostgreSQL ORM | ~15 MB | ✅ gorm.io/gorm ou ent |
| **express** + **express-rate-limit** | REST API | ~5 MB | ✅ net/http + go-chi/chi |
| **tsyringe** | Dependency injection | ~1 MB | ✅ uber-go/fx ou wire |
| **zod** | Validation | ~2 MB | ✅ go-playground/validator |
| **axios** | HTTP client | ~1 MB | ✅ net/http (stdlib) |
| **node-cron** | Scheduler | ~500 KB | ✅ robfig/cron |
| **@alpacahq/alpaca-trade-api** | Alpaca broker | ~3 MB | ✅ alpacahq/alpaca-trade-api-go |

**Total runtime RAM (Node.js)**: ~150 MB idle
**Total runtime RAM (Go estimé)**: ~15-20 MB idle

---

## 2. Problème Majeur: CCXT

### État actuel
- **200+ exchanges** supportés (Binance, OKX, Bybit, Coinbase, Kraken, etc.)
- API unifiée pour trades, positions, balances
- Maintenance active, mises à jour régulières

### Équivalents Go
❌ **Aucune alternative complète**

Options:
1. **Bibliothèques partielles**:
   - `adshao/go-binance` (Binance uniquement) ⭐ 1.5k stars
   - `thrasher-corp/gocryptotrader` ⭐ 2k stars (40 exchanges, qualité variable)
   - Écrire des wrappers REST manuels (énorme effort)

2. **Wrapper FFI CCXT via C/Rust** (complexe, performances perdues)

3. **Micro-architecture hybride**:
   - Core en Go (enclave, gRPC, crypto)
   - Connecteurs CCXT en Node.js (service séparé)
   - Communication via gRPC interne

### Recommandation
**Option 3: Architecture hybride**

```
┌─────────────────────────────────────────┐
│  Enclave Service (Go)                   │
│  - gRPC server                          │
│  - Encryption (AES-256-GCM)             │
│  - Attestation (AMD SEV-SNP)            │
│  - Aggregation                          │
│  - Database (PostgreSQL)                │
│  - REST API                             │
│  └──> gRPC client ───┐                  │
└──────────────────────│──────────────────┘
                       │
                       │ gRPC (localhost)
                       │
┌──────────────────────▼──────────────────┐
│  Exchange Connector Service (Node.js)   │
│  - CCXT wrapper                         │
│  - Alpaca SDK                           │
│  - IBKR Flex                            │
│  - gRPC server (internal)               │
└─────────────────────────────────────────┘
```

**Avantages**:
- Utilise CCXT (200+ exchanges)
- Core Go = gains RAM/CPU principaux (80%)
- Connecteurs isolés (crash n'impacte pas l'enclave)

**Inconvénients**:
- Architecture plus complexe
- Deux langages à maintenir
- Latence inter-process (~1-2ms)

---

## 3. Comparatif Technique: Node.js vs Go

### Dépendances → Équivalents Go

| Node.js Package | Go Package | Notes |
|----------------|------------|-------|
| `@grpc/grpc-js` | `google.golang.org/grpc` | Officiel Google, meilleur perf |
| `@grpc/proto-loader` | `protoc-gen-go` + `protoc-gen-go-grpc` | Codegen statique |
| `@prisma/client` | `gorm.io/gorm` ou `entgo.io/ent` | GORM = simple, Ent = type-safe |
| `express` | `net/http` + `go-chi/chi` | Stdlib + router léger |
| `express-rate-limit` | `golang.org/x/time/rate` | Stdlib extended |
| `tsyringe` | `uber.go/fx` ou `google/wire` | fx=runtime DI, wire=codegen |
| `zod` | `github.com/go-playground/validator` | Validation struct tags |
| `axios` | `net/http` | Stdlib suffisant |
| `node-cron` | `github.com/robfig/cron` | Cron expression parsing |
| `dotenv` | `github.com/joho/godotenv` | .env loader |
| `crypto` (Node.js) | `crypto/aes`, `crypto/cipher` | Stdlib crypto excellent |
| `reflect-metadata` | Go reflection | Built-in language feature |

### Services Spécialisés

| Service | Lib Node.js | Lib Go | LOC estimé |
|---------|-------------|--------|------------|
| AMD SEV-SNP Attestation | `/dev/sev-guest`, `exec snpguest` | Same + `os/exec` | ~200 |
| AES-256-GCM Encryption | `crypto.createCipheriv` | `crypto/aes` + `crypto/cipher` | ~150 |
| TLS Key Generation | `crypto.generateKeyPair` | `crypto/rsa`, `crypto/x509` | ~200 |
| E2E ECIES Encryption | `crypto.createECDH` | `crypto/elliptic`, `crypto/ecdh` | ~300 |
| Report Signing (ECDSA) | `crypto.sign` | `crypto/ecdsa` | ~150 |

---

## 4. Structure Projet Go

### Layout Standard Go
```
zero-knowledge-aggregator/
├── cmd/
│   └── enclave/
│       └── main.go                      # Entry point
├── internal/                            # Code privé (non exportable)
│   ├── server/
│   │   ├── grpc.go                      # gRPC server
│   │   ├── rest.go                      # REST API (net/http)
│   │   └── sse.go                       # SSE log streaming
│   ├── service/
│   │   ├── encryption.go                # AES-256-GCM
│   │   ├── attestation.go               # SEV-SNP
│   │   ├── aggregator.go                # Equity snapshot
│   │   ├── trade_sync.go                # Trade sync orchestrator
│   │   ├── scheduler.go                 # Cron scheduler
│   │   ├── rate_limiter.go              # Sync rate limiting
│   │   ├── key_management.go            # DEK management
│   │   ├── key_derivation.go            # AMD SEV-SNP key derivation
│   │   ├── report_generator.go          # Report generation
│   │   ├── report_signing.go            # ECDSA signing
│   │   ├── tls_generator.go             # TLS cert generation
│   │   ├── e2e_encryption.go            # ECIES E2E encryption
│   │   └── memory_protection.go         # Memory protection
│   ├── connector/
│   │   ├── interface.go                 # IExchangeConnector
│   │   ├── grpc_client.go               # gRPC client vers Node.js
│   │   ├── alpaca.go                    # Alpaca SDK Go
│   │   └── ibkr.go                      # IBKR Flex XML parsing
│   ├── repository/
│   │   ├── snapshot.go                  # GORM model
│   │   ├── user.go
│   │   ├── exchange_connection.go
│   │   ├── sync_status.go
│   │   ├── dek.go
│   │   └── signed_report.go
│   ├── model/                           # Domain models
│   │   ├── snapshot.go
│   │   ├── trade.go
│   │   └── report.go
│   ├── config/
│   │   └── config.go                    # Config loader (GCP metadata)
│   └── logger/
│       └── logger.go                    # Structured logger (slog)
├── pkg/                                 # Code public (exportable)
│   └── proto/
│       ├── enclave.proto                # gRPC definitions
│       ├── enclave.pb.go                # Generated
│       └── enclave_grpc.pb.go           # Generated
├── migrations/                          # SQL migrations (golang-migrate)
├── docker/
│   └── Dockerfile
├── go.mod
├── go.sum
└── Makefile
```

### Conventions Go
- Packages par domaine (pas par type)
- `internal/` = code privé à ce module
- `pkg/` = code réutilisable publiquement
- `cmd/` = points d'entrée binaires
- Tests à côté du code: `service_test.go`

---

## 5. Plan de Migration (Étapes)

### Phase 1: Infrastructure de Base (Semaine 1)
**Objectif**: Projet Go compilable avec structure de base

1. **Initialisation**
   - `go mod init github.com/your-org/enclave`
   - Layout standard (cmd/, internal/, pkg/)
   - Makefile (build, test, proto-gen, docker)

2. **Configuration**
   - Loader de config (env vars + GCP metadata)
   - Logger structuré (`log/slog` ou `uber-go/zap`)
   - Error handling patterns

3. **Database Layer**
   - Choix ORM: GORM vs Ent
   - Migration des modèles Prisma → GORM/Ent
   - Repository pattern

4. **gRPC Server**
   - Compiler `proto/enclave.proto` → Go
   - Server skeleton avec handlers vides
   - TLS configuration

**Livrable**: Binary Go qui démarre, log, et expose gRPC health check

---

### Phase 2: Services Core (Semaine 2-3)

5. **Encryption Services**
   - AES-256-GCM (`crypto/aes` + `crypto/cipher`)
   - Key management (DEK wrapping/unwrapping)
   - Key derivation (AMD SEV-SNP measurement-based)
   - Tests unitaires avec vectors de test

6. **AMD SEV-SNP Attestation**
   - `/dev/sev-guest` interaction
   - `snpguest` CLI wrapper (`os/exec`)
   - TLS fingerprint binding
   - Attestation report parsing

7. **E2E Encryption (ECIES)**
   - ECDH key exchange (`crypto/ecdh`)
   - AES-256-GCM payload encryption
   - Public key fingerprinting

8. **Report Signing (ECDSA)**
   - ECDSA key pair generation (`crypto/ecdsa`)
   - SHA-256 hashing
   - Signature generation/verification

**Livrable**: Core security primitives fonctionnels et testés

---

### Phase 3: Business Logic (Semaine 4-5)

9. **Repository Layer**
   - GORM models pour toutes les tables Prisma
   - CRUD operations
   - Transactions
   - Tests avec base de données de test

10. **Equity Snapshot Aggregator**
    - Port de la logique TypeScript
    - Single-pass classification (optimisations déjà faites)
    - Market breakdown calculation
    - Tests avec données réelles

11. **Trade Sync Service**
    - Orchestration de sync
    - Gestion des erreurs
    - Rate limiting
    - Logging détaillé

12. **Performance Metrics Service**
    - Sharpe, Sortino, Calmar ratios
    - Drawdown calculation
    - Volatility metrics
    - Tests statistiques

**Livrable**: Business logic complète avec tests unitaires

---

### Phase 4: Connecteurs Exchange (Semaine 6)

**Option A: Architecture Hybride (Recommandé)**

13. **Service Node.js CCXT (séparé)**
    - Extraire connecteurs CCXT dans repo séparé
    - Exposer via gRPC (proto séparé)
    - Dockerize séparément
    - Communication localhost uniquement

14. **Client gRPC Go**
    - Client vers service CCXT
    - Interface IExchangeConnector unifiée
    - Circuit breaker + retry logic
    - Timeout configuration

**Option B: Connecteurs Go Natifs (Si faisable)**

15. **Connecteurs REST manuels**
    - Binance API wrapper (~800 LOC)
    - OKX API wrapper (~600 LOC)
    - Bybit API wrapper (~500 LOC)
    - ⚠️ Maintenance continue requise

16. **Alpaca SDK Go**
    - Utiliser `alpacahq/alpaca-trade-api-go`
    - Adapter l'interface

17. **IBKR Flex Parser**
    - XML parsing (`encoding/xml`)
    - Flex query API

**Livrable**: Connecteurs fonctionnels pour exchanges principaux

---

### Phase 5: API Servers (Semaine 7)

18. **REST API Server**
    - `net/http` + `go-chi/chi`
    - Rate limiting (`golang.org/x/time/rate`)
    - Middleware (logging, CORS, auth)
    - Endpoints: /api/v1/attestation, /api/v1/credentials/connect

19. **SSE Log Streaming**
    - HTTP SSE endpoint
    - Broadcast channel pattern
    - Client connection management

20. **Prometheus Metrics**
    - `github.com/prometheus/client_golang`
    - Custom collectors
    - /metrics endpoint

**Livrable**: APIs REST et SSE fonctionnelles

---

### Phase 6: Scheduler & Orchestration (Semaine 8)

21. **Cron Scheduler**
    - `github.com/robfig/cron`
    - Daily sync à 00:00 UTC
    - Rate limiter enforcement
    - Graceful shutdown

22. **Worker Orchestration**
    - EnclaveWorker Go equivalent
    - gRPC handler implementation
    - Error handling + recovery

**Livrable**: Système complet orchestré

---

### Phase 7: Docker & Déploiement (Semaine 9)

23. **Multi-stage Dockerfile**
    ```dockerfile
    FROM golang:1.23-alpine AS builder
    WORKDIR /build
    COPY go.mod go.sum ./
    RUN go mod download
    COPY . .
    RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o enclave cmd/enclave/main.go

    FROM alpine:3.19
    RUN apk add --no-cache ca-certificates
    COPY --from=builder /build/enclave /app/enclave
    EXPOSE 50051 3050
    CMD ["/app/enclave"]
    ```

24. **Docker Compose**
    - Service enclave Go
    - Service CCXT Node.js (si hybride)
    - PostgreSQL
    - Networking

25. **CI/CD**
    - GitHub Actions
    - Build + test
    - Docker build + push
    - Déploiement sur GCP TEE

**Livrable**: Déploiement production ready

---

### Phase 8: Tests & Validation (Semaine 10)

26. **Tests d'Intégration**
    - End-to-end gRPC tests
    - Database integration tests
    - Exchange connector tests (mocks)

27. **Tests de Performance**
    - Benchmarks Go (`testing.B`)
    - Profiling CPU/RAM (pprof)
    - Comparaison Node.js vs Go

28. **Tests de Sécurité**
    - Attestation validation
    - Encryption/decryption roundtrips
    - Memory leak detection

**Livrable**: Suite de tests complète + rapport de performance

---

## 6. Estimation Lignes de Code

### TypeScript actuel → Go équivalent

| Composant | TS (LOC) | Go (LOC) | Ratio | Notes |
|-----------|----------|----------|-------|-------|
| **gRPC Server** | 929 | 800 | 0.86x | Proto codegen plus verbeux |
| **Services** | ~2,500 | ~2,000 | 0.8x | Pas de decorators DI |
| **Repositories** | ~800 | ~600 | 0.75x | GORM plus concis |
| **Connectors** (sans CCXT) | ~1,200 | ~1,500 | 1.25x | API wrappers manuels |
| **REST API** | 333 | 400 | 1.2x | net/http plus verbeux |
| **Config/Utils** | ~500 | ~400 | 0.8x | Stdlib puissant |
| **Types** | ~400 | ~300 | 0.75x | Structs Go plus concis |
| **Validation** | ~300 | ~200 | 0.67x | Struct tags Go |
| **Tests** | ~500 | ~700 | 1.4x | Tests Go plus verbeux |
| **TOTAL (sans CCXT)** | **~7,100** | **~6,900** | **0.97x** | Presque équivalent |

### Avec connecteurs CCXT manuels (+3,000 LOC)
- **Go natif complet**: ~9,900 LOC (+39%)
- **Architecture hybride**: ~6,900 LOC Go + 2,000 LOC Node.js

**Conclusion**: Architecture hybride = **lignes de code équivalentes** avec gains perf.

---

## 7. Gains de Performance Estimés

### RAM Usage

| Métrique | Node.js | Go | Gain |
|----------|---------|-----|------|
| **Idle RAM** | 150 MB | 15-20 MB | **7-10x** |
| **Under load** | 300 MB | 40-60 MB | **5-7x** |
| **CCXT instance** | 50 MB | N/A (service séparé) | Isolé |
| **Total (hybride)** | 150 MB | 80 MB | **1.9x** |

### CPU Usage

| Opération | Node.js | Go | Gain |
|-----------|---------|-----|------|
| **gRPC request** | ~2ms | ~0.5ms | **4x** |
| **Encryption AES-256** | ~1ms | ~0.2ms | **5x** |
| **Trade classification** | ~10ms (optimisé) | ~3ms | **3x** |
| **Database query** | ~5ms | ~3ms | **1.7x** |
| **Aggregation** | ~50ms | ~15ms | **3x** |

### Build Time

| Type | Node.js (tsc) | Go | Gain |
|------|---------------|-----|------|
| **Clean build** | 12s | 3s | **4x** |
| **Incremental** | 4s | 0.8s | **5x** |
| **Docker build** | 5min | 3min | **1.7x** |

### Cold Start

| Environnement | Node.js | Go | Gain |
|---------------|---------|-----|------|
| **Process start** | 500ms | 5ms | **100x** |
| **Database connect** | 300ms | 200ms | **1.5x** |
| **Total ready** | 800ms | 205ms | **4x** |

---

## 8. Risques & Mitigations

### Risques Majeurs

| Risque | Impact | Probabilité | Mitigation |
|--------|--------|-------------|------------|
| **CCXT unavailable in Go** | 🔴 Critique | Certain | Architecture hybride |
| **Prisma → GORM migration bugs** | 🟡 Moyen | Moyen | Tests exhaustifs, migration progressive |
| **Performance non atteinte** | 🟡 Moyen | Faible | Profiling continu, benchmarks |
| **Bugs AMD SEV-SNP** | 🟠 Élevé | Faible | Tests sur hardware réel tôt |
| **Deadline dépassé** | 🟡 Moyen | Moyen | Prioriser features critiques |
| **Régression fonctionnelle** | 🟠 Élevé | Moyen | Suite de tests E2E complète |

### Plan de Contingence
- **Si CCXT bloque**: Utiliser architecture hybride dès le début
- **Si délai dépassé**: Livrer en 2 phases (core Go, puis migration connecteurs)
- **Si bugs critiques**: Rollback vers Node.js possible (Docker swap)

---

## 9. Effort & Timeline

### Estimation Totale
- **Durée**: 10 semaines (2.5 mois)
- **Effort**: 1 développeur full-time
- **Complexité**: Élevée (refactor complet)

### Phases Critiques
1. ✅ **Phase 1-2** (infra + crypto): Fondation solide requise
2. ⚠️ **Phase 4** (connecteurs): Décision architecture hybride vs native
3. 🔍 **Phase 8** (tests): Validation exhaustive avant production

### Jalons (Milestones)
- **Semaine 2**: Binary Go fonctionnel avec gRPC health check
- **Semaine 5**: Business logic complète testée
- **Semaine 7**: APIs exposées fonctionnelles
- **Semaine 10**: Déploiement production + validation

---

## 10. Décision Architecturale Clé

### Architecture Hybride vs Go Pur

#### Option A: Architecture Hybride (Recommandé ✅)

**Pour**:
- ✅ Utilise CCXT (200+ exchanges)
- ✅ Gains perf principaux conservés (core en Go)
- ✅ Délai raisonnable (10 semaines)
- ✅ Maintenance CCXT assurée par communauté
- ✅ Isolation: crash connecteur n'impacte pas enclave

**Contre**:
- ❌ Deux langages à maintenir
- ❌ Complexité déploiement (+1 service)
- ❌ Latence inter-process (~1-2ms)

**Gains estimés**:
- RAM: **1.9x** (150 MB → 80 MB)
- CPU: **2-3x** (core intensif en Go)
- Build: **4x** (12s → 3s)

#### Option B: Go Pur (Non Recommandé ❌)

**Pour**:
- ✅ Single language
- ✅ Gains perf maximaux (5-7x RAM)
- ✅ Déploiement simplifié

**Contre**:
- ❌ Réécrire 40+ connecteurs exchange (~8,000 LOC)
- ❌ Maintenance continue (breaking changes APIs)
- ❌ Délai 6+ mois
- ❌ Qualité inférieure à CCXT

### Recommandation Finale

**→ Architecture Hybride**

Raison: Pragmatique, gains substantiels (80% de Node.js vers Go), délai acceptable, utilise le meilleur de chaque écosystème.

---

## 11. Prochaines Étapes

### Immédiat
1. **Validation technique**:
   - Prototyper gRPC Go server (2h)
   - Tester GORM avec schema Prisma (2h)
   - POC AMD SEV-SNP attestation en Go (4h)

2. **Décision architecture**:
   - Confirmer hybride vs pur Go
   - Valider avec équipe/stakeholders

3. **Setup projet**:
   - Créer repo Go
   - CI/CD pipeline
   - Docker multi-stage

### Phase 1 (Semaine 1)
- Initialiser projet Go avec layout standard
- Migrer configuration + logger
- Setup GORM + migrations
- gRPC server skeleton

### Validation Continue
- Daily commits
- Tests automatisés (CI)
- Profiling RAM/CPU chaque semaine
- Comparaisons Node.js vs Go

---

## 12. Ressources & Dépendances Go

### Bibliothèques Essentielles

```go
// go.mod
module github.com/your-org/enclave

go 1.23

require (
    // gRPC
    google.golang.org/grpc v1.65.0
    google.golang.org/protobuf v1.34.0

    // Database
    gorm.io/gorm v1.25.7
    gorm.io/driver/postgres v1.5.7

    // Web
    github.com/go-chi/chi/v5 v5.0.12
    golang.org/x/time v0.5.0  // rate limiting

    // Crypto
    // stdlib: crypto/aes, crypto/cipher, crypto/ecdsa, crypto/x509

    // Config
    github.com/joho/godotenv v1.5.1

    // Logging
    // stdlib: log/slog (Go 1.21+)

    // Scheduler
    github.com/robfig/cron/v3 v3.0.1

    // Dependency Injection (optional)
    go.uber.org/fx v1.20.1

    // Validation
    github.com/go-playground/validator/v10 v10.19.0

    // Alpaca SDK
    github.com/alpacahq/alpaca-trade-api-go/v3 v3.3.1

    // Prometheus
    github.com/prometheus/client_golang v1.19.0

    // Testing
    github.com/stretchr/testify v1.9.0
    github.com/DATA-DOG/go-sqlmock v1.5.2
)
```

### Outils de Développement

```makefile
# Makefile
.PHONY: build test proto clean docker

build:
	go build -o bin/enclave cmd/enclave/main.go

test:
	go test -v -race -coverprofile=coverage.out ./...

proto:
	protoc --go_out=. --go-grpc_out=. pkg/proto/*.proto

clean:
	rm -rf bin/ coverage.out

docker:
	docker build -t enclave:latest -f docker/Dockerfile .

run:
	go run cmd/enclave/main.go

bench:
	go test -bench=. -benchmem ./...

profile:
	go test -cpuprofile=cpu.prof -memprofile=mem.prof -bench=.
	go tool pprof -http=:8080 cpu.prof
```

---

## Conclusion

La conversion vers Go apporte des gains substantiels:
- **RAM**: 5-10x réduction (architecture hybride: 1.9x)
- **CPU**: 2-4x plus rapide
- **Build**: 4x plus rapide (12s → 3s)
- **Cold start**: 100x plus rapide

**Architecture recommandée**: Hybride (core Go + connecteurs CCXT Node.js)

**Durée**: 10 semaines, 1 développeur full-time

**Effort**: Élevé mais justifié par gains long-terme (coûts infra, performances)

**Risque principal**: CCXT inexistant en Go → mitigé par architecture hybride

**Go/No-Go**: ✅ Recommandé si objectif = optimisation RAM/CPU long-terme
