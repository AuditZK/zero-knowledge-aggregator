# Plan de Migration: Zero-Knowledge Aggregator (TypeScript → Go)

## Vue d'ensemble

Migration de l'Enclave de Node.js/TypeScript vers Go pour améliorer les performances, réduire l'empreinte mémoire, et bénéficier de la compilation native pour l'environnement AMD SEV-SNP.

**Projet source:** `C:\Users\jimmy\Desktop\zero-knowledge-aggregator` (~5,300 LOC TypeScript)
**Projet cible:** `C:\Users\jimmy\Desktop\zero-knowledge-aggregator-go`

---

## Phase 1: Infrastructure de Base

### 1.1 Structure du Projet Go

```
zero-knowledge-aggregator-go/
├── cmd/
│   └── enclave/
│       └── main.go                    # Point d'entrée
├── internal/
│   ├── config/
│   │   └── config.go                  # Configuration (env vars)
│   ├── server/
│   │   ├── grpc.go                    # Serveur gRPC
│   │   ├── rest.go                    # API REST interne
│   │   └── handlers.go                # Handlers gRPC
│   ├── services/
│   │   ├── encryption/
│   │   │   ├── aes.go                 # AES-256-GCM
│   │   │   ├── key_management.go      # Gestion DEK
│   │   │   └── key_derivation.go      # Dérivation depuis SEV-SNP
│   │   ├── sync/
│   │   │   ├── trade_sync.go          # Synchronisation trades
│   │   │   ├── scheduler.go           # Cron 00:00 UTC
│   │   │   └── rate_limiter.go        # Cooldown 23h
│   │   ├── snapshot/
│   │   │   ├── aggregator.go          # Création snapshots
│   │   │   └── classifier.go          # Classification par marché
│   │   ├── metrics/
│   │   │   ├── performance.go         # Sharpe, Sortino, Calmar
│   │   │   └── prometheus.go          # Métriques Prometheus
│   │   ├── report/
│   │   │   ├── generator.go           # Génération rapports
│   │   │   └── signing.go             # Signature ECDSA
│   │   └── attestation/
│   │       └── sev_snp.go             # Vérification SEV-SNP
│   ├── connectors/
│   │   ├── interface.go               # Interface IExchangeConnector
│   │   ├── factory.go                 # Factory pattern
│   │   ├── crypto/
│   │   │   ├── binance.go
│   │   │   ├── bitget.go
│   │   │   ├── bybit.go
│   │   │   ├── okx.go
│   │   │   ├── kucoin.go
│   │   │   ├── mexc.go
│   │   │   ├── coinbase.go
│   │   │   ├── gate.go
│   │   │   └── kraken.go
│   │   └── brokers/
│   │       ├── ibkr.go                # Interactive Brokers Flex
│   │       ├── alpaca.go              # Alpaca Markets
│   │       └── tradestation.go        # TradeStation OAuth
│   ├── repository/
│   │   ├── user.go
│   │   ├── exchange_connection.go
│   │   ├── snapshot.go
│   │   ├── sync_status.go
│   │   ├── dek.go
│   │   └── signed_report.go
│   ├── models/
│   │   ├── user.go
│   │   ├── trade.go
│   │   ├── position.go
│   │   ├── snapshot.go
│   │   ├── connection.go
│   │   └── report.go
│   └── utils/
│       ├── logger.go                  # Structured logging
│       └── time.go                    # Utilitaires date/heure
├── pkg/
│   └── proto/
│       ├── enclave.proto              # Définitions gRPC (copie)
│       └── enclave.pb.go              # Code généré
├── migrations/
│   └── *.sql                          # Migrations SQL (optionnel)
├── certs/                             # Certificats TLS
├── scripts/
│   └── generate_proto.sh              # Génération protobuf
├── Dockerfile
├── docker-compose.yml
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

### 1.2 Dépendances Go

```go
// go.mod
module github.com/trackrecord/enclave

go 1.22

require (
    // gRPC
    google.golang.org/grpc v1.60.0
    google.golang.org/protobuf v1.32.0

    // Database
    github.com/jackc/pgx/v5 v5.5.0      // PostgreSQL driver natif
    // OU
    gorm.io/gorm v1.25.0                // ORM (si préféré)
    gorm.io/driver/postgres v1.5.0

    // Validation
    github.com/go-playground/validator/v10 v10.16.0

    // Configuration
    github.com/spf13/viper v1.18.0

    // Scheduling
    github.com/robfig/cron/v3 v3.0.1

    // HTTP Client (pour exchanges)
    github.com/go-resty/resty/v2 v2.11.0

    // Logging
    go.uber.org/zap v1.26.0

    // Dependency Injection (optionnel)
    github.com/google/wire v0.5.0

    // Testing
    github.com/stretchr/testify v1.8.4

    // Metrics
    github.com/prometheus/client_golang v1.18.0

    // XML parsing (IBKR Flex)
    github.com/beevik/etree v1.2.0
)
```

### 1.3 Fichier Makefile

```makefile
.PHONY: build run test proto clean

build:
	go build -o bin/enclave ./cmd/enclave

run:
	go run ./cmd/enclave

test:
	go test -v ./...

proto:
	protoc --go_out=. --go-grpc_out=. pkg/proto/enclave.proto

clean:
	rm -rf bin/

docker-build:
	docker build -t enclave:latest .

lint:
	golangci-lint run ./...
```

---

## Phase 2: Couche Données (Repository Pattern)

### 2.1 Interface Repository

```go
// internal/repository/interfaces.go
package repository

type UserRepository interface {
    Create(ctx context.Context, uid string) (*models.User, error)
    GetByUID(ctx context.Context, uid string) (*models.User, error)
    GetAll(ctx context.Context) ([]*models.User, error)
}

type ExchangeConnectionRepository interface {
    Create(ctx context.Context, conn *models.ExchangeConnection) error
    GetByUserAndExchange(ctx context.Context, userUID, exchange string) (*models.ExchangeConnection, error)
    GetActiveByUser(ctx context.Context, userUID string) ([]*models.ExchangeConnection, error)
    GetDecryptedCredentials(ctx context.Context, connectionID string) (*models.Credentials, error)
    Delete(ctx context.Context, connectionID string) error
}

type SnapshotRepository interface {
    Upsert(ctx context.Context, snapshot *models.Snapshot) error
    GetByUserAndDateRange(ctx context.Context, userUID string, start, end time.Time) ([]*models.Snapshot, error)
    GetLatestByUser(ctx context.Context, userUID string) (*models.Snapshot, error)
}

type SyncStatusRepository interface {
    Upsert(ctx context.Context, status *models.SyncStatus) error
    GetByUserAndExchange(ctx context.Context, userUID, exchange string) (*models.SyncStatus, error)
}

type DEKRepository interface {
    GetActive(ctx context.Context) (*models.DEK, error)
    Create(ctx context.Context, dek *models.DEK) error
    Rotate(ctx context.Context, newDEK *models.DEK) error
}

type SignedReportRepository interface {
    Create(ctx context.Context, report *models.SignedReport) error
    GetByHash(ctx context.Context, hash string) (*models.SignedReport, error)
    GetByUserAndPeriod(ctx context.Context, userUID string, start, end time.Time, benchmark string) (*models.SignedReport, error)
}
```

### 2.2 Implémentation pgx (Recommandé)

```go
// internal/repository/postgres/user.go
package postgres

import (
    "context"
    "github.com/jackc/pgx/v5/pgxpool"
)

type UserRepo struct {
    pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
    return &UserRepo{pool: pool}
}

func (r *UserRepo) Create(ctx context.Context, uid string) (*models.User, error) {
    query := `
        INSERT INTO users (uid, created_at, updated_at)
        VALUES ($1, NOW(), NOW())
        RETURNING id, uid, created_at, updated_at
    `
    var user models.User
    err := r.pool.QueryRow(ctx, query, uid).Scan(
        &user.ID, &user.UID, &user.CreatedAt, &user.UpdatedAt,
    )
    return &user, err
}
```

---

## Phase 3: Services Cryptographiques

### 3.1 Service Encryption (AES-256-GCM)

```go
// internal/services/encryption/aes.go
package encryption

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
)

type EncryptionService struct {
    keyManager *KeyManagementService
}

func NewEncryptionService(km *KeyManagementService) *EncryptionService {
    return &EncryptionService{keyManager: km}
}

func (s *EncryptionService) Encrypt(plaintext []byte) (ciphertext, iv, authTag []byte, err error) {
    dek, err := s.keyManager.GetCurrentDEK()
    if err != nil {
        return nil, nil, nil, err
    }

    block, err := aes.NewCipher(dek)
    if err != nil {
        return nil, nil, nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, nil, nil, err
    }

    iv = make([]byte, gcm.NonceSize())
    if _, err := rand.Read(iv); err != nil {
        return nil, nil, nil, err
    }

    sealed := gcm.Seal(nil, iv, plaintext, nil)
    // GCM appends auth tag at the end
    ciphertext = sealed[:len(sealed)-gcm.Overhead()]
    authTag = sealed[len(sealed)-gcm.Overhead():]

    return ciphertext, iv, authTag, nil
}

func (s *EncryptionService) Decrypt(ciphertext, iv, authTag []byte) ([]byte, error) {
    dek, err := s.keyManager.GetCurrentDEK()
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(dek)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    sealed := append(ciphertext, authTag...)
    return gcm.Open(nil, iv, sealed, nil)
}
```

### 3.2 Service Key Management

```go
// internal/services/encryption/key_management.go
package encryption

type KeyManagementService struct {
    dekRepo     repository.DEKRepository
    derivation  *KeyDerivationService
    currentDEK  []byte
    mu          sync.RWMutex
}

func (s *KeyManagementService) GetCurrentDEK() ([]byte, error) {
    s.mu.RLock()
    if s.currentDEK != nil {
        defer s.mu.RUnlock()
        return s.currentDEK, nil
    }
    s.mu.RUnlock()

    // Load from DB and unwrap
    return s.loadAndUnwrapDEK()
}

func (s *KeyManagementService) RotateDEK() error {
    // Generate new DEK
    // Wrap with master key
    // Store in DB
    // Update current DEK in memory
}
```

### 3.3 Service Key Derivation (SEV-SNP)

```go
// internal/services/encryption/key_derivation.go
package encryption

import (
    "crypto/sha256"
    "golang.org/x/crypto/hkdf"
    "io"
)

type KeyDerivationService struct {
    masterKey []byte
}

func (s *KeyDerivationService) DeriveMasterKey() error {
    // En production: lire depuis /dev/sev-guest
    // En dev: utiliser une clé fixe
    measurement, err := s.getSEVMeasurement()
    if err != nil {
        return err
    }

    hash := sha256.New
    reader := hkdf.New(hash, measurement, nil, []byte("enclave-master-key"))

    s.masterKey = make([]byte, 32)
    _, err = io.ReadFull(reader, s.masterKey)
    return err
}

func (s *KeyDerivationService) WrapKey(dek []byte) (wrapped, iv, tag []byte, err error) {
    // Encrypt DEK with master key
}

func (s *KeyDerivationService) UnwrapKey(wrapped, iv, tag []byte) ([]byte, error) {
    // Decrypt DEK with master key
}
```

---

## Phase 4: Connecteurs Exchange

### 4.1 Interface Connecteur

```go
// internal/connectors/interface.go
package connectors

type ExchangeConnector interface {
    TestConnection(ctx context.Context) error
    GetBalance(ctx context.Context) (*BalanceData, error)
    GetCurrentPositions(ctx context.Context) ([]*PositionData, error)
    GetTrades(ctx context.Context, start, end time.Time) ([]*TradeData, error)
    GetExchangeName() string
    SupportsFeature(feature ExchangeFeature) bool
}

type BalanceData struct {
    Balance       float64 `json:"balance"`
    Equity        float64 `json:"equity"`
    UnrealizedPnL float64 `json:"unrealizedPnl"`
    Currency      string  `json:"currency"`
    MarginUsed    float64 `json:"marginUsed,omitempty"`
}

type TradeData struct {
    TradeID     string    `json:"tradeId"`
    Symbol      string    `json:"symbol"`
    Side        string    `json:"side"` // "buy" | "sell"
    Quantity    float64   `json:"quantity"`
    Price       float64   `json:"price"`
    Fee         float64   `json:"fee"`
    FeeCurrency string    `json:"feeCurrency"`
    Timestamp   time.Time `json:"timestamp"`
    RealizedPnL float64   `json:"realizedPnl,omitempty"`
    MarketType  string    `json:"marketType"` // spot, swap, futures, options
}

type PositionData struct {
    Symbol        string  `json:"symbol"`
    Side          string  `json:"side"` // "long" | "short"
    Size          float64 `json:"size"`
    EntryPrice    float64 `json:"entryPrice"`
    MarkPrice     float64 `json:"markPrice"`
    UnrealizedPnL float64 `json:"unrealizedPnl"`
}

type ExchangeFeature int

const (
    FeatureSpot ExchangeFeature = iota
    FeatureFutures
    FeatureMargin
    FeatureOptions
)
```

### 4.2 Factory Pattern

```go
// internal/connectors/factory.go
package connectors

import "errors"

var ErrUnsupportedExchange = errors.New("unsupported exchange")

type ConnectorFactory struct {
    encryption *encryption.EncryptionService
}

func NewConnectorFactory(enc *encryption.EncryptionService) *ConnectorFactory {
    return &ConnectorFactory{encryption: enc}
}

func (f *ConnectorFactory) Create(creds *models.Credentials) (ExchangeConnector, error) {
    switch creds.Exchange {
    // Crypto exchanges
    case "binance":
        return crypto.NewBinanceConnector(creds), nil
    case "bitget":
        return crypto.NewBitgetConnector(creds), nil
    case "bybit":
        return crypto.NewBybitConnector(creds), nil
    case "okx":
        return crypto.NewOKXConnector(creds), nil
    case "kucoin":
        return crypto.NewKucoinConnector(creds), nil
    case "mexc":
        return crypto.NewMEXCConnector(creds), nil
    case "coinbase":
        return crypto.NewCoinbaseConnector(creds), nil
    case "gate":
        return crypto.NewGateConnector(creds), nil
    case "kraken":
        return crypto.NewKrakenConnector(creds), nil

    // Traditional brokers
    case "ibkr":
        return brokers.NewIBKRConnector(creds), nil
    case "alpaca":
        return brokers.NewAlpacaConnector(creds), nil
    case "tradestation":
        return brokers.NewTradeStationConnector(creds), nil

    default:
        return nil, ErrUnsupportedExchange
    }
}
```

### 4.3 Exemple: Connecteur Binance

```go
// internal/connectors/crypto/binance.go
package crypto

import (
    "context"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "net/url"
    "strconv"
    "time"

    "github.com/go-resty/resty/v2"
)

const (
    binanceBaseURL   = "https://api.binance.com"
    binanceFuturesURL = "https://fapi.binance.com"
)

type BinanceConnector struct {
    apiKey    string
    apiSecret string
    client    *resty.Client
}

func NewBinanceConnector(creds *models.Credentials) *BinanceConnector {
    client := resty.New().
        SetTimeout(30 * time.Second).
        SetRetryCount(3)

    return &BinanceConnector{
        apiKey:    creds.APIKey,
        apiSecret: creds.APISecret,
        client:    client,
    }
}

func (c *BinanceConnector) sign(params url.Values) string {
    h := hmac.New(sha256.New, []byte(c.apiSecret))
    h.Write([]byte(params.Encode()))
    return hex.EncodeToString(h.Sum(nil))
}

func (c *BinanceConnector) GetBalance(ctx context.Context) (*BalanceData, error) {
    // Spot balance
    spotBalance, err := c.getSpotBalance(ctx)
    if err != nil {
        return nil, err
    }

    // Futures balance (si supporté)
    futuresBalance, _ := c.getFuturesBalance(ctx)

    return &BalanceData{
        Balance:       spotBalance.Free,
        Equity:        spotBalance.Total + futuresBalance.Equity,
        UnrealizedPnL: futuresBalance.UnrealizedPnL,
        Currency:      "USDT",
    }, nil
}

func (c *BinanceConnector) getSpotBalance(ctx context.Context) (*spotBalance, error) {
    params := url.Values{}
    params.Set("timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
    params.Set("signature", c.sign(params))

    var result struct {
        Balances []struct {
            Asset  string `json:"asset"`
            Free   string `json:"free"`
            Locked string `json:"locked"`
        } `json:"balances"`
    }

    resp, err := c.client.R().
        SetContext(ctx).
        SetHeader("X-MBX-APIKEY", c.apiKey).
        SetQueryParamsFromValues(params).
        SetResult(&result).
        Get(binanceBaseURL + "/api/v3/account")

    if err != nil {
        return nil, err
    }
    if resp.IsError() {
        return nil, fmt.Errorf("binance API error: %s", resp.String())
    }

    // Calculer total USDT
    var total, free float64
    for _, b := range result.Balances {
        if b.Asset == "USDT" {
            free, _ = strconv.ParseFloat(b.Free, 64)
            locked, _ := strconv.ParseFloat(b.Locked, 64)
            total = free + locked
            break
        }
    }

    return &spotBalance{Free: free, Total: total}, nil
}

func (c *BinanceConnector) GetTrades(ctx context.Context, start, end time.Time) ([]*TradeData, error) {
    // Implémenter récupération trades spot + futures
    // Pagination si nécessaire
}

func (c *BinanceConnector) GetExchangeName() string {
    return "binance"
}

func (c *BinanceConnector) SupportsFeature(f ExchangeFeature) bool {
    return true // Binance supporte tout
}
```

### 4.4 Exemple: Connecteur IBKR Flex

```go
// internal/connectors/brokers/ibkr.go
package brokers

import (
    "context"
    "encoding/xml"
    "fmt"
    "time"

    "github.com/beevik/etree"
    "github.com/go-resty/resty/v2"
)

const ibkrFlexURL = "https://gdcdyn.interactivebrokers.com/Universal/servlet/FlexStatementService.SendRequest"

type IBKRConnector struct {
    token   string
    queryID string
    client  *resty.Client
}

func NewIBKRConnector(creds *models.Credentials) *IBKRConnector {
    return &IBKRConnector{
        token:   creds.APIKey,    // Flex Token
        queryID: creds.APISecret, // Flex Query ID
        client:  resty.New().SetTimeout(60 * time.Second),
    }
}

func (c *IBKRConnector) GetBalance(ctx context.Context) (*BalanceData, error) {
    // Request Flex report
    referenceCode, err := c.requestFlexReport(ctx)
    if err != nil {
        return nil, err
    }

    // Poll for report (peut prendre jusqu'à 2 minutes)
    report, err := c.waitForReport(ctx, referenceCode)
    if err != nil {
        return nil, err
    }

    // Parse XML
    return c.parseBalanceFromFlexReport(report)
}

func (c *IBKRConnector) requestFlexReport(ctx context.Context) (string, error) {
    resp, err := c.client.R().
        SetContext(ctx).
        SetQueryParams(map[string]string{
            "t": c.token,
            "q": c.queryID,
            "v": "3",
        }).
        Get(ibkrFlexURL)

    if err != nil {
        return "", err
    }

    // Parse XML response pour obtenir reference code
    doc := etree.NewDocument()
    if err := doc.ReadFromString(resp.String()); err != nil {
        return "", err
    }

    refCode := doc.FindElement("//ReferenceCode")
    if refCode == nil {
        return "", fmt.Errorf("no reference code in response")
    }

    return refCode.Text(), nil
}

func (c *IBKRConnector) GetTrades(ctx context.Context, start, end time.Time) ([]*TradeData, error) {
    // Similar: request report, parse trades from XML
}

func (c *IBKRConnector) GetExchangeName() string {
    return "ibkr"
}
```

---

## Phase 5: Services Métier

### 5.1 Trade Sync Service

```go
// internal/services/sync/trade_sync.go
package sync

type TradeSyncService struct {
    connFactory *connectors.ConnectorFactory
    connRepo    repository.ExchangeConnectionRepository
    snapshotSvc *snapshot.AggregatorService
    logger      *zap.Logger
}

func (s *TradeSyncService) SyncUserTrades(ctx context.Context, userUID string) error {
    connections, err := s.connRepo.GetActiveByUser(ctx, userUID)
    if err != nil {
        return err
    }

    var wg sync.WaitGroup
    errCh := make(chan error, len(connections))

    for _, conn := range connections {
        wg.Add(1)
        go func(c *models.ExchangeConnection) {
            defer wg.Done()
            if err := s.syncExchange(ctx, userUID, c); err != nil {
                errCh <- err
            }
        }(conn)
    }

    wg.Wait()
    close(errCh)

    // Collect errors
    var errs []error
    for err := range errCh {
        errs = append(errs, err)
    }

    if len(errs) > 0 {
        return fmt.Errorf("sync errors: %v", errs)
    }
    return nil
}

func (s *TradeSyncService) syncExchange(ctx context.Context, userUID string, conn *models.ExchangeConnection) error {
    // 1. Decrypt credentials
    creds, err := s.connRepo.GetDecryptedCredentials(ctx, conn.ID)
    if err != nil {
        return err
    }

    // 2. Create connector
    connector, err := s.connFactory.Create(creds)
    if err != nil {
        return err
    }

    // 3. Get balance & positions
    balance, err := connector.GetBalance(ctx)
    if err != nil {
        return err
    }

    positions, _ := connector.GetCurrentPositions(ctx)

    // 4. Get trades (memory only - NEVER persisted)
    now := time.Now().UTC()
    startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
    trades, err := connector.GetTrades(ctx, startOfDay, now)
    if err != nil {
        s.logger.Warn("failed to get trades", zap.Error(err))
    }

    // 5. Create snapshot (trades aggregated, then discarded)
    return s.snapshotSvc.CreateSnapshot(ctx, userUID, conn.Exchange, balance, positions, trades)
}
```

### 5.2 Snapshot Aggregator

```go
// internal/services/snapshot/aggregator.go
package snapshot

type AggregatorService struct {
    snapshotRepo repository.SnapshotRepository
    classifier   *MarketClassifier
}

func (s *AggregatorService) CreateSnapshot(
    ctx context.Context,
    userUID string,
    exchange string,
    balance *connectors.BalanceData,
    positions []*connectors.PositionData,
    trades []*connectors.TradeData, // Memory only - discarded after aggregation
) error {
    // Classify trades by market type
    breakdown := s.classifier.ClassifyTrades(trades)

    // Calculate aggregates
    var totalFees, totalVolume float64
    for _, t := range trades {
        totalFees += t.Fee
        totalVolume += t.Quantity * t.Price
    }

    snapshot := &models.Snapshot{
        UserUID:          userUID,
        Exchange:         exchange,
        Timestamp:        time.Now().UTC().Truncate(24 * time.Hour),
        TotalEquity:      balance.Equity,
        RealizedBalance:  balance.Balance,
        UnrealizedPnL:    balance.UnrealizedPnL,
        TotalTrades:      len(trades),
        TotalVolume:      totalVolume,
        TotalFees:        totalFees,
        BreakdownByMarket: breakdown, // JSON field
    }

    // Upsert snapshot
    err := s.snapshotRepo.Upsert(ctx, snapshot)

    // CRITICAL: trades are now garbage collected
    // Individual trades NEVER touch the database

    return err
}
```

### 5.3 Daily Sync Scheduler

```go
// internal/services/sync/scheduler.go
package sync

import (
    "github.com/robfig/cron/v3"
)

type DailySyncScheduler struct {
    cron        *cron.Cron
    syncService *TradeSyncService
    userRepo    repository.UserRepository
    logger      *zap.Logger
}

func NewDailySyncScheduler(sync *TradeSyncService, users repository.UserRepository) *DailySyncScheduler {
    return &DailySyncScheduler{
        cron:        cron.New(cron.WithLocation(time.UTC)),
        syncService: sync,
        userRepo:    users,
        logger:      zap.L(),
    }
}

func (s *DailySyncScheduler) Start() error {
    // Run at 00:00 UTC every day
    _, err := s.cron.AddFunc("0 0 * * *", s.executeDailySync)
    if err != nil {
        return err
    }

    s.cron.Start()
    s.logger.Info("daily sync scheduler started", zap.String("schedule", "0 0 * * * UTC"))
    return nil
}

func (s *DailySyncScheduler) Stop() {
    ctx := s.cron.Stop()
    <-ctx.Done()
}

func (s *DailySyncScheduler) executeDailySync() {
    ctx := context.Background()

    users, err := s.userRepo.GetAll(ctx)
    if err != nil {
        s.logger.Error("failed to get users for daily sync", zap.Error(err))
        return
    }

    for _, user := range users {
        if err := s.syncService.SyncUserTrades(ctx, user.UID); err != nil {
            s.logger.Error("failed to sync user",
                zap.String("userUID", user.UID),
                zap.Error(err),
            )
        }
    }
}
```

### 5.4 Performance Metrics Service

```go
// internal/services/metrics/performance.go
package metrics

import (
    "math"
    "sort"
)

type PerformanceService struct {
    snapshotRepo repository.SnapshotRepository
}

type PerformanceMetrics struct {
    SharpeRatio       float64 `json:"sharpeRatio"`
    SortinoRatio      float64 `json:"sortinoRatio"`
    CalmarRatio       float64 `json:"calmarRatio"`
    Volatility        float64 `json:"volatility"`
    DownsideDeviation float64 `json:"downsideDeviation"`
    MaxDrawdown       float64 `json:"maxDrawdown"`
    MaxDrawdownDays   int     `json:"maxDrawdownDays"`
    WinRate           float64 `json:"winRate"`
    ProfitFactor      float64 `json:"profitFactor"`
    TotalReturn       float64 `json:"totalReturn"`
}

func (s *PerformanceService) Calculate(ctx context.Context, userUID string, start, end time.Time) (*PerformanceMetrics, error) {
    snapshots, err := s.snapshotRepo.GetByUserAndDateRange(ctx, userUID, start, end)
    if err != nil {
        return nil, err
    }

    if len(snapshots) < 2 {
        return nil, errors.New("insufficient data for metrics calculation")
    }

    // Calculate daily returns
    returns := s.calculateDailyReturns(snapshots)

    // Calculate metrics
    avgReturn := mean(returns)
    stdDev := stddev(returns)
    downsideDev := s.downsideDeviation(returns, 0)
    maxDD, maxDDDays := s.maxDrawdown(snapshots)

    annualizedReturn := avgReturn * 252
    annualizedVol := stdDev * math.Sqrt(252)

    return &PerformanceMetrics{
        SharpeRatio:       annualizedReturn / annualizedVol,
        SortinoRatio:      annualizedReturn / (downsideDev * math.Sqrt(252)),
        CalmarRatio:       annualizedReturn / math.Abs(maxDD),
        Volatility:        annualizedVol,
        DownsideDeviation: downsideDev * math.Sqrt(252),
        MaxDrawdown:       maxDD,
        MaxDrawdownDays:   maxDDDays,
        WinRate:           s.winRate(returns),
        ProfitFactor:      s.profitFactor(returns),
        TotalReturn:       s.totalReturn(snapshots),
    }, nil
}

func (s *PerformanceService) calculateDailyReturns(snapshots []*models.Snapshot) []float64 {
    // Sort by timestamp
    sort.Slice(snapshots, func(i, j int) bool {
        return snapshots[i].Timestamp.Before(snapshots[j].Timestamp)
    })

    returns := make([]float64, 0, len(snapshots)-1)
    for i := 1; i < len(snapshots); i++ {
        prev := snapshots[i-1].TotalEquity
        curr := snapshots[i].TotalEquity
        if prev > 0 {
            returns = append(returns, (curr-prev)/prev)
        }
    }
    return returns
}

func (s *PerformanceService) maxDrawdown(snapshots []*models.Snapshot) (float64, int) {
    if len(snapshots) == 0 {
        return 0, 0
    }

    var maxDD float64
    var maxDDDays int
    peak := snapshots[0].TotalEquity
    peakIdx := 0

    for i, snap := range snapshots {
        if snap.TotalEquity > peak {
            peak = snap.TotalEquity
            peakIdx = i
        }
        dd := (peak - snap.TotalEquity) / peak
        if dd > maxDD {
            maxDD = dd
            maxDDDays = i - peakIdx
        }
    }

    return maxDD, maxDDDays
}
```

---

## Phase 6: Serveur gRPC

### 6.1 Définition Proto (Copie)

```protobuf
// pkg/proto/enclave.proto
syntax = "proto3";

package enclave;

option go_package = "github.com/trackrecord/enclave/pkg/proto";

service EnclaveService {
  rpc ProcessSyncJob(SyncJobRequest) returns (SyncJobResponse);
  rpc GetAggregatedMetrics(AggregatedMetricsRequest) returns (AggregatedMetricsResponse);
  rpc GetSnapshotTimeSeries(SnapshotTimeSeriesRequest) returns (SnapshotTimeSeriesResponse);
  rpc CreateUserConnection(CreateUserConnectionRequest) returns (CreateUserConnectionResponse);
  rpc GetPerformanceMetrics(PerformanceMetricsRequest) returns (PerformanceMetricsResponse);
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
  rpc GenerateSignedReport(ReportRequest) returns (SignedReportResponse);
  rpc VerifyReportSignature(VerifySignatureRequest) returns (VerifySignatureResponse);
}

// ... (copier les messages depuis le projet source)
```

### 6.2 Implémentation Serveur

```go
// internal/server/grpc.go
package server

import (
    "context"
    "crypto/tls"
    "net"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"

    pb "github.com/trackrecord/enclave/pkg/proto"
)

type EnclaveServer struct {
    pb.UnimplementedEnclaveServiceServer

    syncService    *sync.TradeSyncService
    snapshotRepo   repository.SnapshotRepository
    connRepo       repository.ExchangeConnectionRepository
    metricsService *metrics.PerformanceService
    reportService  *report.GeneratorService
    encryption     *encryption.EncryptionService
    logger         *zap.Logger
}

func NewEnclaveServer(/* dependencies */) *EnclaveServer {
    return &EnclaveServer{/* init */}
}

func (s *EnclaveServer) Start(port int, tlsConfig *tls.Config) error {
    lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        return err
    }

    creds := credentials.NewTLS(tlsConfig)
    grpcServer := grpc.NewServer(
        grpc.Creds(creds),
        grpc.UnaryInterceptor(s.loggingInterceptor),
    )

    pb.RegisterEnclaveServiceServer(grpcServer, s)

    s.logger.Info("gRPC server starting", zap.Int("port", port))
    return grpcServer.Serve(lis)
}

func (s *EnclaveServer) ProcessSyncJob(ctx context.Context, req *pb.SyncJobRequest) (*pb.SyncJobResponse, error) {
    if err := s.validateSyncRequest(req); err != nil {
        return nil, status.Error(codes.InvalidArgument, err.Error())
    }

    err := s.syncService.SyncUserTrades(ctx, req.UserUid)
    if err != nil {
        return nil, status.Error(codes.Internal, err.Error())
    }

    return &pb.SyncJobResponse{
        Success: true,
        Message: "Sync completed successfully",
    }, nil
}

func (s *EnclaveServer) GetAggregatedMetrics(ctx context.Context, req *pb.AggregatedMetricsRequest) (*pb.AggregatedMetricsResponse, error) {
    // Implementation
}

func (s *EnclaveServer) CreateUserConnection(ctx context.Context, req *pb.CreateUserConnectionRequest) (*pb.CreateUserConnectionResponse, error) {
    // 1. Validate
    // 2. Encrypt credentials
    // 3. Store in DB
    // 4. Test connection
}

func (s *EnclaveServer) GetPerformanceMetrics(ctx context.Context, req *pb.PerformanceMetricsRequest) (*pb.PerformanceMetricsResponse, error) {
    start := time.Unix(req.StartTimestamp, 0)
    end := time.Unix(req.EndTimestamp, 0)

    metrics, err := s.metricsService.Calculate(ctx, req.UserUid, start, end)
    if err != nil {
        return nil, status.Error(codes.Internal, err.Error())
    }

    return &pb.PerformanceMetricsResponse{
        SharpeRatio:  metrics.SharpeRatio,
        SortinoRatio: metrics.SortinoRatio,
        // ... map all fields
    }, nil
}

func (s *EnclaveServer) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
    return &pb.HealthCheckResponse{
        Status:    "healthy",
        Version:   "1.0.0",
        Timestamp: time.Now().Unix(),
    }, nil
}
```

---

## Phase 7: Point d'Entrée

### 7.1 Main

```go
// cmd/enclave/main.go
package main

import (
    "context"
    "os"
    "os/signal"
    "syscall"

    "github.com/trackrecord/enclave/internal/config"
    "github.com/trackrecord/enclave/internal/server"
    "go.uber.org/zap"
)

func main() {
    // 1. Initialize logger
    logger, _ := zap.NewProduction()
    defer logger.Sync()
    zap.ReplaceGlobals(logger)

    // 2. Load configuration
    cfg, err := config.Load()
    if err != nil {
        logger.Fatal("failed to load config", zap.Error(err))
    }

    // 3. Initialize dependencies (DI)
    app, err := initializeApp(cfg)
    if err != nil {
        logger.Fatal("failed to initialize app", zap.Error(err))
    }

    // 4. Start servers
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // gRPC server
    go func() {
        if err := app.grpcServer.Start(cfg.GRPCPort, cfg.TLSConfig); err != nil {
            logger.Fatal("gRPC server failed", zap.Error(err))
        }
    }()

    // REST server (internal monitoring)
    go func() {
        if err := app.restServer.Start(cfg.RESTPort); err != nil {
            logger.Fatal("REST server failed", zap.Error(err))
        }
    }()

    // Daily sync scheduler
    if err := app.scheduler.Start(); err != nil {
        logger.Fatal("scheduler failed to start", zap.Error(err))
    }

    logger.Info("enclave started",
        zap.Int("grpc_port", cfg.GRPCPort),
        zap.Int("rest_port", cfg.RESTPort),
    )

    // 5. Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    logger.Info("shutting down...")
    app.scheduler.Stop()
    cancel()
}
```

### 7.2 Configuration

```go
// internal/config/config.go
package config

import (
    "crypto/tls"
    "github.com/spf13/viper"
)

type Config struct {
    // Server
    GRPCPort int
    RESTPort int

    // Database
    DatabaseURL string

    // Security
    EnclaveMode bool
    SEVSNP      bool

    // TLS
    TLSConfig *tls.Config

    // Logging
    LogLevel string
}

func Load() (*Config, error) {
    viper.SetConfigName(".env")
    viper.SetConfigType("env")
    viper.AddConfigPath(".")

    viper.AutomaticEnv()

    // Defaults
    viper.SetDefault("GRPC_PORT", 50051)
    viper.SetDefault("REST_PORT", 3050)
    viper.SetDefault("LOG_LEVEL", "info")

    if err := viper.ReadInConfig(); err != nil {
        // Config file not found is OK
    }

    return &Config{
        GRPCPort:    viper.GetInt("GRPC_PORT"),
        RESTPort:    viper.GetInt("REST_PORT"),
        DatabaseURL: viper.GetString("DATABASE_URL"),
        EnclaveMode: viper.GetBool("ENCLAVE_MODE"),
        SEVSNP:      viper.GetBool("AMD_SEV_SNP"),
        LogLevel:    viper.GetString("LOG_LEVEL"),
    }, nil
}
```

---

## Phase 8: Tests

### 8.1 Tests Unitaires

```go
// internal/services/encryption/aes_test.go
package encryption_test

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/trackrecord/enclave/internal/services/encryption"
)

func TestEncryptDecrypt(t *testing.T) {
    km := encryption.NewKeyManagementService(nil, nil) // mock
    svc := encryption.NewEncryptionService(km)

    plaintext := []byte("api_key_secret_123")

    ciphertext, iv, tag, err := svc.Encrypt(plaintext)
    require.NoError(t, err)

    decrypted, err := svc.Decrypt(ciphertext, iv, tag)
    require.NoError(t, err)

    assert.Equal(t, plaintext, decrypted)
}
```

### 8.2 Tests d'Intégration

```go
// internal/server/grpc_test.go
package server_test

func TestEnclaveServer_HealthCheck(t *testing.T) {
    // Setup test server
    // Make gRPC call
    // Assert response
}
```

---

## Ordre de Migration Recommandé

### Semaine 1-2: Infrastructure
1. [ ] Setup projet Go (go.mod, structure)
2. [ ] Configuration (viper)
3. [ ] Logging (zap)
4. [ ] Database connection (pgx)

### Semaine 3-4: Couche Données
5. [ ] Models Go
6. [ ] Repositories (user, connection, snapshot)
7. [ ] Tests repositories

### Semaine 5-6: Cryptographie
8. [ ] AES-256-GCM encryption
9. [ ] Key management
10. [ ] Key derivation (SEV-SNP stub)
11. [ ] Report signing (ECDSA)

### Semaine 7-9: Connecteurs Exchange
12. [ ] Interface connector
13. [ ] Factory pattern
14. [ ] Binance connector
15. [ ] Autres crypto connectors (Bybit, OKX, etc.)
16. [ ] IBKR Flex connector
17. [ ] Alpaca connector
18. [ ] TradeStation connector

### Semaine 10-11: Services Métier
19. [ ] Trade sync service
20. [ ] Snapshot aggregator
21. [ ] Market classifier
22. [ ] Daily sync scheduler
23. [ ] Rate limiter

### Semaine 12-13: Métriques & Rapports
24. [ ] Performance metrics service
25. [ ] Report generator
26. [ ] Prometheus metrics

### Semaine 14-15: gRPC Server
27. [ ] Proto compilation
28. [ ] Server implementation
29. [ ] All 8 RPC methods
30. [ ] mTLS setup

### Semaine 16: Finalisation
31. [ ] Tests d'intégration complets
32. [ ] Docker build
33. [ ] Documentation
34. [ ] Performance benchmarks

---

## Avantages de Go pour ce Projet

1. **Performance**: Compilation native, pas de runtime overhead
2. **Mémoire**: Contrôle fin, GC efficace, empreinte réduite
3. **Concurrence**: Goroutines natives pour sync parallèle
4. **Crypto**: Bibliothèque standard complète (AES, ECDSA, SHA)
5. **gRPC**: Support natif excellent
6. **Single binary**: Déploiement simplifié dans l'enclave
7. **Type safety**: Pas de surprises runtime comme TypeScript

---

## Risques et Mitigations

| Risque | Impact | Mitigation |
|--------|--------|------------|
| Pas de CCXT en Go | Haut | Implémenter manuellement chaque exchange (REST APIs bien documentées) |
| Complexité IBKR Flex | Moyen | Parser XML robuste, tests extensifs |
| Migration DEK existants | Haut | Script de migration, période de coexistence |
| Différences comportementales | Moyen | Tests de parité TypeScript ↔ Go |

---

## Ressources

- [Go gRPC](https://grpc.io/docs/languages/go/)
- [pgx PostgreSQL driver](https://github.com/jackc/pgx)
- [Zap logger](https://github.com/uber-go/zap)
- [Binance API docs](https://binance-docs.github.io/apidocs/)
- [IBKR Flex docs](https://www.interactivebrokers.com/en/software/am/am/reports/activityflexqueries.htm)
