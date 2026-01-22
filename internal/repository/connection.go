package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")

// ExchangeConnection represents an encrypted exchange connection
type ExchangeConnection struct {
	ID                  string    `json:"id"`
	UserUID             string    `json:"user_uid"`
	Exchange            string    `json:"exchange"`
	Label               string    `json:"label"`
	EncryptedAPIKey     string    `json:"encrypted_api_key"`
	APIKeyIV            string    `json:"api_key_iv"`
	APIKeyAuthTag       string    `json:"api_key_auth_tag"`
	EncryptedAPISecret  string    `json:"encrypted_api_secret"`
	APISecretIV         string    `json:"api_secret_iv"`
	APISecretAuthTag    string    `json:"api_secret_auth_tag"`
	EncryptedPassphrase string    `json:"encrypted_passphrase,omitempty"`
	PassphraseIV        string    `json:"passphrase_iv,omitempty"`
	PassphraseAuthTag   string    `json:"passphrase_auth_tag,omitempty"`
	IsActive            bool      `json:"is_active"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// ConnectionRepo handles exchange connection persistence
type ConnectionRepo struct {
	pool *pgxpool.Pool
}

// NewConnectionRepo creates a new connection repository
func NewConnectionRepo(pool *pgxpool.Pool) *ConnectionRepo {
	return &ConnectionRepo{pool: pool}
}

// Create inserts a new exchange connection
func (r *ConnectionRepo) Create(ctx context.Context, conn *ExchangeConnection) error {
	query := `
		INSERT INTO exchange_connections (
			user_uid, exchange, label,
			encrypted_api_key, api_key_iv, api_key_auth_tag,
			encrypted_api_secret, api_secret_iv, api_secret_auth_tag,
			encrypted_passphrase, passphrase_iv, passphrase_auth_tag,
			is_active, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		) RETURNING id`

	now := time.Now().UTC()
	conn.CreatedAt = now
	conn.UpdatedAt = now
	conn.IsActive = true

	return r.pool.QueryRow(ctx, query,
		conn.UserUID, conn.Exchange, conn.Label,
		conn.EncryptedAPIKey, conn.APIKeyIV, conn.APIKeyAuthTag,
		conn.EncryptedAPISecret, conn.APISecretIV, conn.APISecretAuthTag,
		conn.EncryptedPassphrase, conn.PassphraseIV, conn.PassphraseAuthTag,
		conn.IsActive, conn.CreatedAt, conn.UpdatedAt,
	).Scan(&conn.ID)
}

// GetByUserAndExchange retrieves a connection by user and exchange
func (r *ConnectionRepo) GetByUserAndExchange(ctx context.Context, userUID, exchange string) (*ExchangeConnection, error) {
	query := `
		SELECT id, user_uid, exchange, label,
			encrypted_api_key, api_key_iv, api_key_auth_tag,
			encrypted_api_secret, api_secret_iv, api_secret_auth_tag,
			encrypted_passphrase, passphrase_iv, passphrase_auth_tag,
			is_active, created_at, updated_at
		FROM exchange_connections
		WHERE user_uid = $1 AND exchange = $2 AND is_active = true`

	var conn ExchangeConnection
	err := r.pool.QueryRow(ctx, query, userUID, exchange).Scan(
		&conn.ID, &conn.UserUID, &conn.Exchange, &conn.Label,
		&conn.EncryptedAPIKey, &conn.APIKeyIV, &conn.APIKeyAuthTag,
		&conn.EncryptedAPISecret, &conn.APISecretIV, &conn.APISecretAuthTag,
		&conn.EncryptedPassphrase, &conn.PassphraseIV, &conn.PassphraseAuthTag,
		&conn.IsActive, &conn.CreatedAt, &conn.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return &conn, nil
}

// GetActiveByUser retrieves all active connections for a user
func (r *ConnectionRepo) GetActiveByUser(ctx context.Context, userUID string) ([]*ExchangeConnection, error) {
	query := `
		SELECT id, user_uid, exchange, label,
			encrypted_api_key, api_key_iv, api_key_auth_tag,
			encrypted_api_secret, api_secret_iv, api_secret_auth_tag,
			encrypted_passphrase, passphrase_iv, passphrase_auth_tag,
			is_active, created_at, updated_at
		FROM exchange_connections
		WHERE user_uid = $1 AND is_active = true
		ORDER BY created_at`

	rows, err := r.pool.Query(ctx, query, userUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connections []*ExchangeConnection
	for rows.Next() {
		var conn ExchangeConnection
		if err := rows.Scan(
			&conn.ID, &conn.UserUID, &conn.Exchange, &conn.Label,
			&conn.EncryptedAPIKey, &conn.APIKeyIV, &conn.APIKeyAuthTag,
			&conn.EncryptedAPISecret, &conn.APISecretIV, &conn.APISecretAuthTag,
			&conn.EncryptedPassphrase, &conn.PassphraseIV, &conn.PassphraseAuthTag,
			&conn.IsActive, &conn.CreatedAt, &conn.UpdatedAt,
		); err != nil {
			return nil, err
		}
		connections = append(connections, &conn)
	}

	return connections, rows.Err()
}

// Deactivate soft-deletes a connection
func (r *ConnectionRepo) Deactivate(ctx context.Context, id string) error {
	query := `UPDATE exchange_connections SET is_active = false, updated_at = $1 WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, time.Now().UTC(), id)
	return err
}
