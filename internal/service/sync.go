package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/trackrecord/enclave/internal/connector"
	"github.com/trackrecord/enclave/internal/repository"
	"go.uber.org/zap"
)

// SyncService orchestrates exchange synchronization
type SyncService struct {
	connSvc      *ConnectionService
	snapshotRepo *repository.SnapshotRepo
	factory      *connector.Factory
	logger       *zap.Logger
}

// NewSyncService creates a new sync service
func NewSyncService(
	connSvc *ConnectionService,
	snapshotRepo *repository.SnapshotRepo,
	logger *zap.Logger,
) *SyncService {
	return &SyncService{
		connSvc:      connSvc,
		snapshotRepo: snapshotRepo,
		factory:      connector.NewFactory(),
		logger:       logger,
	}
}

// SyncResult holds the result of a sync operation
type SyncResult struct {
	UserUID            string    `json:"user_uid"`
	Exchange           string    `json:"exchange"`
	Success            bool      `json:"success"`
	TradeCount         int       `json:"trade_count"`
	SnapshotEquity     float64   `json:"snapshot_equity"`
	SnapshotTimestamp  time.Time `json:"snapshot_timestamp"`
	Error              string    `json:"error,omitempty"`
}

// SyncUser synchronizes all exchanges for a user (manual sync).
// Each exchange is individually checked for manual sync blocking.
func (s *SyncService) SyncUser(ctx context.Context, userUID string) ([]*SyncResult, error) {
	connections, err := s.connSvc.GetActiveConnections(ctx, userUID)
	if err != nil {
		return nil, fmt.Errorf("get connections: %w", err)
	}

	if len(connections) == 0 {
		return nil, fmt.Errorf("no active connections for user %s", userUID)
	}

	var (
		results []*SyncResult
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	for _, conn := range connections {
		wg.Add(1)
		go func(c *repository.ExchangeConnection) {
			defer wg.Done()

			var result *SyncResult
			if !s.isManualSyncAllowed(ctx, userUID, c.Exchange) {
				result = &SyncResult{
					UserUID:  userUID,
					Exchange: c.Exchange,
					Error:    "manual sync blocked: snapshot already exists. Only the hourly scheduler can sync after initial snapshot.",
				}
			} else {
				result = s.syncExchange(ctx, userUID, c.Exchange)
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(conn)
	}

	wg.Wait()
	return results, nil
}

// SyncUserScheduled synchronizes all exchanges for a user (scheduler path - bypasses manual block)
func (s *SyncService) SyncUserScheduled(ctx context.Context, userUID string) ([]*SyncResult, error) {
	connections, err := s.connSvc.GetActiveConnections(ctx, userUID)
	if err != nil {
		return nil, fmt.Errorf("get connections: %w", err)
	}

	if len(connections) == 0 {
		return nil, fmt.Errorf("no active connections for user %s", userUID)
	}

	var (
		results []*SyncResult
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	for _, conn := range connections {
		wg.Add(1)
		go func(c *repository.ExchangeConnection) {
			defer wg.Done()

			result := s.syncExchange(ctx, userUID, c.Exchange)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(conn)
	}

	wg.Wait()
	return results, nil
}

// SyncExchange synchronizes a single exchange for a user (manual sync).
// Blocks if a snapshot already exists for this user+exchange (anti-cherry-picking).
func (s *SyncService) SyncExchange(ctx context.Context, userUID, exchange string) *SyncResult {
	// Check if manual sync is allowed (no existing snapshot means first sync is OK)
	if !s.isManualSyncAllowed(ctx, userUID, exchange) {
		return &SyncResult{
			UserUID:  userUID,
			Exchange: exchange,
			Error:    "manual sync blocked: snapshot already exists. Only the hourly scheduler can sync after initial snapshot.",
		}
	}
	return s.syncExchange(ctx, userUID, exchange)
}

// SyncExchangeScheduled is used by the hourly scheduler - bypasses manual sync block
func (s *SyncService) SyncExchangeScheduled(ctx context.Context, userUID, exchange string) *SyncResult {
	return s.syncExchange(ctx, userUID, exchange)
}

// isManualSyncAllowed checks if a manual sync is permitted.
// Returns false if any snapshot already exists for the user+exchange (anti-cherry-picking).
func (s *SyncService) isManualSyncAllowed(ctx context.Context, userUID, exchange string) bool {
	// Check if any snapshot exists for this user+exchange
	snapshots, err := s.snapshotRepo.GetByUserAndDateRange(ctx, userUID,
		time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Now().UTC(),
	)
	if err != nil {
		// On error, allow sync (fail open for first-time users)
		return true
	}

	for _, snap := range snapshots {
		if snap.Exchange == exchange {
			return false
		}
	}
	return true
}

func (s *SyncService) syncExchange(ctx context.Context, userUID, exchange string) *SyncResult {
	result := &SyncResult{
		UserUID:  userUID,
		Exchange: exchange,
	}

	// 1. Get decrypted credentials
	creds, err := s.connSvc.GetDecryptedCredentials(ctx, userUID, exchange)
	if err != nil {
		result.Error = fmt.Sprintf("get credentials: %v", err)
		s.logger.Error("sync failed: get credentials",
			zap.String("user_uid", userUID),
			zap.String("exchange", exchange),
			zap.Error(err),
		)
		return result
	}

	// 2. Create connector
	conn, err := s.factory.Create(&connector.Credentials{
		Exchange:   exchange,
		APIKey:     creds.APIKey,
		APISecret:  creds.APISecret,
		Passphrase: creds.Passphrase,
	})
	if err != nil {
		result.Error = fmt.Sprintf("create connector: %v", err)
		return result
	}

	// 3. Get balance
	balance, err := conn.GetBalance(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("get balance: %v", err)
		s.logger.Error("sync failed: get balance",
			zap.String("user_uid", userUID),
			zap.String("exchange", exchange),
			zap.Error(err),
		)
		return result
	}

	// 4. Get trades for today (memory only - will be aggregated then discarded)
	now := time.Now().UTC()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	trades, _ := conn.GetTrades(ctx, startOfDay, now)

	// 5. Aggregate trades by market type
	breakdown := s.aggregateTrades(trades)

	// 6. Create snapshot
	snapshot := &repository.Snapshot{
		UserUID:         userUID,
		Exchange:        exchange,
		Timestamp:       startOfDay,
		TotalEquity:     balance.Equity,
		RealizedBalance: balance.Available,
		UnrealizedPnL:   balance.UnrealizedPnL,
		TotalTrades:     len(trades),
		TotalVolume:     breakdown.totalVolume(),
		TotalFees:       breakdown.totalFees(),
		Breakdown:       breakdown.toRepo(),
	}

	if err := s.snapshotRepo.Upsert(ctx, snapshot); err != nil {
		result.Error = fmt.Sprintf("save snapshot: %v", err)
		s.logger.Error("sync failed: save snapshot",
			zap.String("user_uid", userUID),
			zap.String("exchange", exchange),
			zap.Error(err),
		)
		return result
	}

	// Success - trades are now garbage collected (never persisted)
	result.Success = true
	result.TradeCount = len(trades)
	result.SnapshotEquity = balance.Equity
	result.SnapshotTimestamp = startOfDay

	s.logger.Info("sync completed",
		zap.String("user_uid", userUID),
		zap.String("exchange", exchange),
		zap.Int("trades", len(trades)),
		zap.Float64("equity", balance.Equity),
	)

	return result
}

// aggregatedBreakdown holds aggregated trade data
type aggregatedBreakdown struct {
	spot        marketAgg
	swap        marketAgg
	futures     marketAgg
	options     marketAgg
	margin      marketAgg
	earn        marketAgg
	cfd         marketAgg
	forex       marketAgg
	commodities marketAgg
}

type marketAgg struct {
	volume float64
	trades int
	fees   float64
}

func (s *SyncService) aggregateTrades(trades []*connector.Trade) *aggregatedBreakdown {
	agg := &aggregatedBreakdown{}

	for _, t := range trades {
		volume := t.Price * t.Quantity
		ma := &agg.spot

		switch t.MarketType {
		case connector.MarketSwap:
			ma = &agg.swap
		case connector.MarketFutures:
			ma = &agg.futures
		case connector.MarketOptions:
			ma = &agg.options
		case connector.MarketMargin:
			ma = &agg.margin
		case connector.MarketEarn:
			ma = &agg.earn
		case connector.MarketCFD:
			ma = &agg.cfd
		case connector.MarketForex:
			ma = &agg.forex
		case connector.MarketCommodities:
			ma = &agg.commodities
		}

		ma.volume += volume
		ma.trades++
		ma.fees += t.Fee
	}

	return agg
}

func (a *aggregatedBreakdown) totalVolume() float64 {
	return a.spot.volume + a.swap.volume + a.futures.volume + a.options.volume +
		a.margin.volume + a.earn.volume + a.cfd.volume + a.forex.volume + a.commodities.volume
}

func (a *aggregatedBreakdown) totalFees() float64 {
	return a.spot.fees + a.swap.fees + a.futures.fees + a.options.fees +
		a.margin.fees + a.earn.fees + a.cfd.fees + a.forex.fees + a.commodities.fees
}

func (a *aggregatedBreakdown) toRepo() *repository.MarketBreakdown {
	breakdown := &repository.MarketBreakdown{}

	if a.spot.trades > 0 {
		breakdown.Spot = &repository.MarketMetrics{
			Volume:      a.spot.volume,
			Trades:      a.spot.trades,
			TradingFees: a.spot.fees,
		}
	}

	if a.swap.trades > 0 {
		breakdown.Swap = &repository.MarketMetrics{
			Volume:      a.swap.volume,
			Trades:      a.swap.trades,
			TradingFees: a.swap.fees,
		}
	}

	if a.futures.trades > 0 {
		breakdown.Futures = &repository.MarketMetrics{
			Volume:      a.futures.volume,
			Trades:      a.futures.trades,
			TradingFees: a.futures.fees,
		}
	}

	if a.options.trades > 0 {
		breakdown.Options = &repository.MarketMetrics{
			Volume:      a.options.volume,
			Trades:      a.options.trades,
			TradingFees: a.options.fees,
		}
	}

	if a.margin.trades > 0 {
		breakdown.Margin = &repository.MarketMetrics{
			Volume:      a.margin.volume,
			Trades:      a.margin.trades,
			TradingFees: a.margin.fees,
		}
	}

	if a.earn.trades > 0 {
		breakdown.Earn = &repository.MarketMetrics{
			Volume:      a.earn.volume,
			Trades:      a.earn.trades,
			TradingFees: a.earn.fees,
		}
	}

	if a.cfd.trades > 0 {
		breakdown.CFD = &repository.MarketMetrics{
			Volume:      a.cfd.volume,
			Trades:      a.cfd.trades,
			TradingFees: a.cfd.fees,
		}
	}

	if a.forex.trades > 0 {
		breakdown.Forex = &repository.MarketMetrics{
			Volume:      a.forex.volume,
			Trades:      a.forex.trades,
			TradingFees: a.forex.fees,
		}
	}

	if a.commodities.trades > 0 {
		breakdown.Commodities = &repository.MarketMetrics{
			Volume:      a.commodities.volume,
			Trades:      a.commodities.trades,
			TradingFees: a.commodities.fees,
		}
	}

	return breakdown
}
