package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SyncStatus represents the sync state for a user/exchange/label combination
type SyncStatus struct {
	ID           string     `json:"id"`
	UserUID      string     `json:"user_uid"`
	Exchange     string     `json:"exchange"`
	Label        string     `json:"label"`
	LastSyncTime *time.Time `json:"last_sync_time,omitempty"`
	Status       string     `json:"status"` // "pending", "syncing", "completed", "error"
	TotalTrades  int        `json:"total_trades"`
	ErrorMessage string     `json:"error_message,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// SyncStatusRepo handles sync status persistence
type SyncStatusRepo struct {
	pool *pgxpool.Pool
}

// NewSyncStatusRepo creates a new sync status repository
func NewSyncStatusRepo(pool *pgxpool.Pool) *SyncStatusRepo {
	return &SyncStatusRepo{pool: pool}
}

// Upsert creates or updates a sync status
func (r *SyncStatusRepo) Upsert(ctx context.Context, s *SyncStatus) error {
	query := `
		INSERT INTO sync_statuses (user_uid, exchange, label, last_sync_time, status, total_trades, error_message, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		ON CONFLICT (user_uid, exchange, label)
		DO UPDATE SET
			last_sync_time = EXCLUDED.last_sync_time,
			status = EXCLUDED.status,
			total_trades = EXCLUDED.total_trades,
			error_message = EXCLUDED.error_message,
			updated_at = NOW()
		RETURNING id`

	return r.pool.QueryRow(ctx, query,
		s.UserUID, s.Exchange, s.Label, s.LastSyncTime, s.Status, s.TotalTrades, s.ErrorMessage,
	).Scan(&s.ID)
}

// GetByUserExchangeLabel retrieves a specific sync status
func (r *SyncStatusRepo) GetByUserExchangeLabel(ctx context.Context, userUID, exchange, label string) (*SyncStatus, error) {
	query := `
		SELECT id, user_uid, exchange, label, last_sync_time, status, total_trades, error_message, created_at, updated_at
		FROM sync_statuses
		WHERE user_uid = $1 AND exchange = $2 AND label = $3`

	var s SyncStatus
	err := r.pool.QueryRow(ctx, query, userUID, exchange, label).Scan(
		&s.ID, &s.UserUID, &s.Exchange, &s.Label, &s.LastSyncTime,
		&s.Status, &s.TotalTrades, &s.ErrorMessage, &s.CreatedAt, &s.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// GetByUser retrieves all sync statuses for a user
func (r *SyncStatusRepo) GetByUser(ctx context.Context, userUID string) ([]*SyncStatus, error) {
	query := `
		SELECT id, user_uid, exchange, label, last_sync_time, status, total_trades, error_message, created_at, updated_at
		FROM sync_statuses
		WHERE user_uid = $1
		ORDER BY updated_at DESC`

	rows, err := r.pool.Query(ctx, query, userUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statuses []*SyncStatus
	for rows.Next() {
		var s SyncStatus
		if err := rows.Scan(
			&s.ID, &s.UserUID, &s.Exchange, &s.Label, &s.LastSyncTime,
			&s.Status, &s.TotalTrades, &s.ErrorMessage, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		statuses = append(statuses, &s)
	}
	return statuses, rows.Err()
}

// UpdateStatus updates the status field for a given sync status
func (r *SyncStatusRepo) UpdateStatus(ctx context.Context, userUID, exchange, label, status string, errMsg string) error {
	query := `
		UPDATE sync_statuses
		SET status = $1, error_message = $2, updated_at = NOW()
		WHERE user_uid = $3 AND exchange = $4 AND label = $5`

	_, err := r.pool.Exec(ctx, query, status, errMsg, userUID, exchange, label)
	return err
}

// GetPending returns all pending or syncing statuses
func (r *SyncStatusRepo) GetPending(ctx context.Context) ([]*SyncStatus, error) {
	query := `
		SELECT id, user_uid, exchange, label, last_sync_time, status, total_trades, error_message, created_at, updated_at
		FROM sync_statuses
		WHERE status IN ('pending', 'syncing')
		ORDER BY updated_at ASC`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statuses []*SyncStatus
	for rows.Next() {
		var s SyncStatus
		if err := rows.Scan(
			&s.ID, &s.UserUID, &s.Exchange, &s.Label, &s.LastSyncTime,
			&s.Status, &s.TotalTrades, &s.ErrorMessage, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		statuses = append(statuses, &s)
	}
	return statuses, rows.Err()
}

// GetErrors returns all sync statuses with errors
func (r *SyncStatusRepo) GetErrors(ctx context.Context) ([]*SyncStatus, error) {
	query := `
		SELECT id, user_uid, exchange, label, last_sync_time, status, total_trades, error_message, created_at, updated_at
		FROM sync_statuses
		WHERE status = 'error'
		ORDER BY updated_at DESC`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statuses []*SyncStatus
	for rows.Next() {
		var s SyncStatus
		if err := rows.Scan(
			&s.ID, &s.UserUID, &s.Exchange, &s.Label, &s.LastSyncTime,
			&s.Status, &s.TotalTrades, &s.ErrorMessage, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		statuses = append(statuses, &s)
	}
	return statuses, rows.Err()
}
