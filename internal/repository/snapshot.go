package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Snapshot represents a daily equity snapshot
type Snapshot struct {
	ID              string           `json:"id"`
	UserUID         string           `json:"user_uid"`
	Exchange        string           `json:"exchange"`
	Timestamp       time.Time        `json:"timestamp"` // 00:00 UTC
	TotalEquity     float64          `json:"total_equity"`
	RealizedBalance float64          `json:"realized_balance"`
	UnrealizedPnL   float64          `json:"unrealized_pnl"`
	Deposits        float64          `json:"deposits"`
	Withdrawals     float64          `json:"withdrawals"`
	TotalTrades     int              `json:"total_trades"`
	TotalVolume     float64          `json:"total_volume"`
	TotalFees       float64          `json:"total_fees"`
	Breakdown       *MarketBreakdown `json:"breakdown,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
}

// MarketBreakdown holds metrics per market type
type MarketBreakdown struct {
	Spot    *MarketMetrics `json:"spot,omitempty"`
	Swap    *MarketMetrics `json:"swap,omitempty"`
	Futures *MarketMetrics `json:"futures,omitempty"`
	Options *MarketMetrics `json:"options,omitempty"`
}

// MarketMetrics holds trading metrics for a market type
type MarketMetrics struct {
	Volume      float64 `json:"volume"`
	Trades      int     `json:"trades"`
	TradingFees float64 `json:"trading_fees"`
	FundingFees float64 `json:"funding_fees"`
}

// SnapshotRepo handles snapshot persistence
type SnapshotRepo struct {
	pool *pgxpool.Pool
}

// NewSnapshotRepo creates a new snapshot repository
func NewSnapshotRepo(pool *pgxpool.Pool) *SnapshotRepo {
	return &SnapshotRepo{pool: pool}
}

// Upsert creates or updates a snapshot for a user/exchange/date
func (r *SnapshotRepo) Upsert(ctx context.Context, s *Snapshot) error {
	breakdownJSON, _ := json.Marshal(s.Breakdown)

	query := `
		INSERT INTO snapshot_data (
			user_uid, exchange, timestamp,
			total_equity, realized_balance, unrealized_pnl,
			deposits, withdrawals, total_trades, total_volume, total_fees,
			breakdown_by_market, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (user_uid, exchange, timestamp)
		DO UPDATE SET
			total_equity = EXCLUDED.total_equity,
			realized_balance = EXCLUDED.realized_balance,
			unrealized_pnl = EXCLUDED.unrealized_pnl,
			deposits = EXCLUDED.deposits,
			withdrawals = EXCLUDED.withdrawals,
			total_trades = EXCLUDED.total_trades,
			total_volume = EXCLUDED.total_volume,
			total_fees = EXCLUDED.total_fees,
			breakdown_by_market = EXCLUDED.breakdown_by_market
		RETURNING id`

	return r.pool.QueryRow(ctx, query,
		s.UserUID, s.Exchange, s.Timestamp,
		s.TotalEquity, s.RealizedBalance, s.UnrealizedPnL,
		s.Deposits, s.Withdrawals, s.TotalTrades, s.TotalVolume, s.TotalFees,
		breakdownJSON, time.Now().UTC(),
	).Scan(&s.ID)
}

// GetByUserAndDateRange returns snapshots for a user within a date range
func (r *SnapshotRepo) GetByUserAndDateRange(ctx context.Context, userUID string, start, end time.Time) ([]*Snapshot, error) {
	query := `
		SELECT id, user_uid, exchange, timestamp,
			total_equity, realized_balance, unrealized_pnl,
			deposits, withdrawals, total_trades, total_volume, total_fees,
			breakdown_by_market, created_at
		FROM snapshot_data
		WHERE user_uid = $1 AND timestamp >= $2 AND timestamp <= $3
		ORDER BY timestamp`

	rows, err := r.pool.Query(ctx, query, userUID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanSnapshots(rows)
}

// GetLatestByUser returns the most recent snapshot for a user
func (r *SnapshotRepo) GetLatestByUser(ctx context.Context, userUID string) (*Snapshot, error) {
	query := `
		SELECT id, user_uid, exchange, timestamp,
			total_equity, realized_balance, unrealized_pnl,
			deposits, withdrawals, total_trades, total_volume, total_fees,
			breakdown_by_market, created_at
		FROM snapshot_data
		WHERE user_uid = $1
		ORDER BY timestamp DESC
		LIMIT 1`

	rows, err := r.pool.Query(ctx, query, userUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	snapshots, err := r.scanSnapshots(rows)
	if err != nil {
		return nil, err
	}

	if len(snapshots) == 0 {
		return nil, ErrNotFound
	}

	return snapshots[0], nil
}

// GetByUserExchangeAndDate returns a specific snapshot
func (r *SnapshotRepo) GetByUserExchangeAndDate(ctx context.Context, userUID, exchange string, date time.Time) (*Snapshot, error) {
	query := `
		SELECT id, user_uid, exchange, timestamp,
			total_equity, realized_balance, unrealized_pnl,
			deposits, withdrawals, total_trades, total_volume, total_fees,
			breakdown_by_market, created_at
		FROM snapshot_data
		WHERE user_uid = $1 AND exchange = $2 AND timestamp = $3`

	rows, err := r.pool.Query(ctx, query, userUID, exchange, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	snapshots, err := r.scanSnapshots(rows)
	if err != nil {
		return nil, err
	}

	if len(snapshots) == 0 {
		return nil, ErrNotFound
	}

	return snapshots[0], nil
}

func (r *SnapshotRepo) scanSnapshots(rows pgx.Rows) ([]*Snapshot, error) {
	var snapshots []*Snapshot

	for rows.Next() {
		var s Snapshot
		var breakdownJSON []byte

		err := rows.Scan(
			&s.ID, &s.UserUID, &s.Exchange, &s.Timestamp,
			&s.TotalEquity, &s.RealizedBalance, &s.UnrealizedPnL,
			&s.Deposits, &s.Withdrawals, &s.TotalTrades, &s.TotalVolume, &s.TotalFees,
			&breakdownJSON, &s.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if len(breakdownJSON) > 0 {
			json.Unmarshal(breakdownJSON, &s.Breakdown)
		}

		snapshots = append(snapshots, &s)
	}

	return snapshots, rows.Err()
}
