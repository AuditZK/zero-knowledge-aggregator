package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// User represents a user in the system
type User struct {
	ID           string    `json:"id"`
	UID          string    `json:"uid"`
	PlatformHash *string   `json:"platform_hash,omitempty"` // SHA-256 of platform user ID
	SyncInterval string    `json:"sync_interval"`           // "hourly" or "daily"
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserRepo handles user persistence
type UserRepo struct {
	pool *pgxpool.Pool
}

// NewUserRepo creates a new user repository
func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

// GetOrCreate gets a user by UID or creates one if not exists
func (r *UserRepo) GetOrCreate(ctx context.Context, uid string) (*User, error) {
	query := `
		INSERT INTO users (uid, created_at, updated_at)
		VALUES ($1, NOW(), NOW())
		ON CONFLICT (uid) DO UPDATE SET updated_at = NOW()
		RETURNING id, uid, platform_hash, sync_interval, created_at, updated_at`

	var user User
	err := r.pool.QueryRow(ctx, query, uid).Scan(
		&user.ID, &user.UID, &user.PlatformHash, &user.SyncInterval, &user.CreatedAt, &user.UpdatedAt,
	)
	return &user, err
}

// GetOrCreateWithPlatformHash gets or creates a user and sets platform_hash if not already set
func (r *UserRepo) GetOrCreateWithPlatformHash(ctx context.Context, uid, platformUserID string) (*User, error) {
	hash := HashPlatformID(platformUserID)
	query := `
		INSERT INTO users (uid, platform_hash, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (uid) DO UPDATE SET
			platform_hash = COALESCE(users.platform_hash, $2),
			updated_at = NOW()
		RETURNING id, uid, platform_hash, sync_interval, created_at, updated_at`

	var user User
	err := r.pool.QueryRow(ctx, query, uid, hash).Scan(
		&user.ID, &user.UID, &user.PlatformHash, &user.SyncInterval, &user.CreatedAt, &user.UpdatedAt,
	)
	return &user, err
}

// GetAllWithConnections returns all users that have at least one active connection
func (r *UserRepo) GetAllWithConnections(ctx context.Context) ([]*User, error) {
	query := `
		SELECT DISTINCT u.id, u.uid, u.platform_hash, u.sync_interval, u.created_at, u.updated_at
		FROM users u
		INNER JOIN exchange_connections ec ON ec.user_uid = u.uid
		WHERE ec.is_active = true
		ORDER BY u.created_at`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.UID, &u.PlatformHash, &u.SyncInterval, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, &u)
	}

	return users, rows.Err()
}

// GetByUID returns a user by their UID
func (r *UserRepo) GetByUID(ctx context.Context, uid string) (*User, error) {
	query := `
		SELECT id, uid, platform_hash, sync_interval, created_at, updated_at
		FROM users
		WHERE uid = $1`

	var user User
	err := r.pool.QueryRow(ctx, query, uid).Scan(
		&user.ID, &user.UID, &user.PlatformHash, &user.SyncInterval, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// UpdateSyncInterval updates a user's sync interval
func (r *UserRepo) UpdateSyncInterval(ctx context.Context, uid string, interval string) error {
	if interval != "hourly" && interval != "daily" {
		interval = "hourly"
	}
	query := `UPDATE users SET sync_interval = $1, updated_at = NOW() WHERE uid = $2`
	_, err := r.pool.Exec(ctx, query, interval, uid)
	return err
}

// HashPlatformID returns the SHA-256 hex hash of a platform user ID
func HashPlatformID(platformUserID string) string {
	h := sha256.Sum256([]byte(platformUserID))
	return hex.EncodeToString(h[:])
}
