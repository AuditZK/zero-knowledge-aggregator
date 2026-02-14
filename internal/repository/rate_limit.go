package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RateLimitLog represents a sync rate limit entry
type RateLimitLog struct {
	ID           string    `json:"id"`
	UserUID      string    `json:"user_uid"`
	Exchange     string    `json:"exchange"`
	Label        string    `json:"label"`
	LastSyncTime time.Time `json:"last_sync_time"`
	SyncCount    int       `json:"sync_count"`
	CreatedAt    time.Time `json:"created_at"`
}

// RateLimitRepo handles rate limit log persistence
type RateLimitRepo struct {
	pool *pgxpool.Pool
}

// NewRateLimitRepo creates a new rate limit repository
func NewRateLimitRepo(pool *pgxpool.Pool) *RateLimitRepo {
	return &RateLimitRepo{pool: pool}
}

// GetByKey retrieves a rate limit log by user+exchange+label
func (r *RateLimitRepo) GetByKey(ctx context.Context, userUID, exchange, label string) (*RateLimitLog, error) {
	query := `
		SELECT id, user_uid, exchange, label, last_sync_time, sync_count, created_at
		FROM sync_rate_limit_logs
		WHERE user_uid = $1 AND exchange = $2 AND label = $3`

	var log RateLimitLog
	err := r.pool.QueryRow(ctx, query, userUID, exchange, label).Scan(
		&log.ID, &log.UserUID, &log.Exchange, &log.Label,
		&log.LastSyncTime, &log.SyncCount, &log.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &log, nil
}

// RecordSync upserts a sync event for rate limiting
func (r *RateLimitRepo) RecordSync(ctx context.Context, userUID, exchange, label string) error {
	query := `
		INSERT INTO sync_rate_limit_logs (user_uid, exchange, label, last_sync_time, sync_count, created_at)
		VALUES ($1, $2, $3, NOW(), 1, NOW())
		ON CONFLICT (user_uid, exchange, label)
		DO UPDATE SET
			last_sync_time = NOW(),
			sync_count = sync_rate_limit_logs.sync_count + 1`

	_, err := r.pool.Exec(ctx, query, userUID, exchange, label)
	return err
}

// CleanupOldLogs deletes rate limit logs older than the given duration
func (r *RateLimitRepo) CleanupOldLogs(ctx context.Context, retention time.Duration) (int64, error) {
	query := `DELETE FROM sync_rate_limit_logs WHERE last_sync_time < $1`
	tag, err := r.pool.Exec(ctx, query, time.Now().UTC().Add(-retention))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
