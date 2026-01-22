package service

import (
	"context"
	"fmt"

	"github.com/trackrecord/enclave/internal/encryption"
	"github.com/trackrecord/enclave/internal/repository"
)

// Credentials holds decrypted API credentials
type Credentials struct {
	UserUID    string
	Exchange   string
	APIKey     string
	APISecret  string
	Passphrase string
}

// ConnectionService handles exchange connection business logic
type ConnectionService struct {
	repo       *repository.ConnectionRepo
	encryption *encryption.Service
}

// NewConnectionService creates a new connection service
func NewConnectionService(repo *repository.ConnectionRepo, enc *encryption.Service) *ConnectionService {
	return &ConnectionService{
		repo:       repo,
		encryption: enc,
	}
}

// CreateConnectionRequest is the input for creating a connection
type CreateConnectionRequest struct {
	UserUID    string
	Exchange   string
	Label      string
	APIKey     string
	APISecret  string
	Passphrase string
}

// Create encrypts and stores a new exchange connection
func (s *ConnectionService) Create(ctx context.Context, req *CreateConnectionRequest) error {
	// Encrypt API key
	apiKeyEnc, err := s.encryption.EncryptString(req.APIKey)
	if err != nil {
		return fmt.Errorf("encrypt api key: %w", err)
	}

	// Encrypt API secret
	apiSecretEnc, err := s.encryption.EncryptString(req.APISecret)
	if err != nil {
		return fmt.Errorf("encrypt api secret: %w", err)
	}

	// Encrypt passphrase (if present)
	var passphraseEnc *encryption.EncryptedData
	if req.Passphrase != "" {
		passphraseEnc, err = s.encryption.EncryptString(req.Passphrase)
		if err != nil {
			return fmt.Errorf("encrypt passphrase: %w", err)
		}
	}

	conn := &repository.ExchangeConnection{
		UserUID:            req.UserUID,
		Exchange:           req.Exchange,
		Label:              req.Label,
		EncryptedAPIKey:    apiKeyEnc.Ciphertext,
		APIKeyIV:           apiKeyEnc.IV,
		APIKeyAuthTag:      apiKeyEnc.AuthTag,
		EncryptedAPISecret: apiSecretEnc.Ciphertext,
		APISecretIV:        apiSecretEnc.IV,
		APISecretAuthTag:   apiSecretEnc.AuthTag,
	}

	if passphraseEnc != nil {
		conn.EncryptedPassphrase = passphraseEnc.Ciphertext
		conn.PassphraseIV = passphraseEnc.IV
		conn.PassphraseAuthTag = passphraseEnc.AuthTag
	}

	return s.repo.Create(ctx, conn)
}

// GetDecryptedCredentials retrieves and decrypts credentials for a connection
func (s *ConnectionService) GetDecryptedCredentials(ctx context.Context, userUID, exchange string) (*Credentials, error) {
	conn, err := s.repo.GetByUserAndExchange(ctx, userUID, exchange)
	if err != nil {
		return nil, err
	}

	// Decrypt API key
	apiKey, err := s.encryption.DecryptString(&encryption.EncryptedData{
		Ciphertext: conn.EncryptedAPIKey,
		IV:         conn.APIKeyIV,
		AuthTag:    conn.APIKeyAuthTag,
	})
	if err != nil {
		return nil, fmt.Errorf("decrypt api key: %w", err)
	}

	// Decrypt API secret
	apiSecret, err := s.encryption.DecryptString(&encryption.EncryptedData{
		Ciphertext: conn.EncryptedAPISecret,
		IV:         conn.APISecretIV,
		AuthTag:    conn.APISecretAuthTag,
	})
	if err != nil {
		return nil, fmt.Errorf("decrypt api secret: %w", err)
	}

	// Decrypt passphrase (if present)
	var passphrase string
	if conn.EncryptedPassphrase != "" {
		passphrase, err = s.encryption.DecryptString(&encryption.EncryptedData{
			Ciphertext: conn.EncryptedPassphrase,
			IV:         conn.PassphraseIV,
			AuthTag:    conn.PassphraseAuthTag,
		})
		if err != nil {
			return nil, fmt.Errorf("decrypt passphrase: %w", err)
		}
	}

	return &Credentials{
		UserUID:    conn.UserUID,
		Exchange:   conn.Exchange,
		APIKey:     apiKey,
		APISecret:  apiSecret,
		Passphrase: passphrase,
	}, nil
}

// GetActiveConnections returns all active connections for a user (encrypted)
func (s *ConnectionService) GetActiveConnections(ctx context.Context, userUID string) ([]*repository.ExchangeConnection, error) {
	return s.repo.GetActiveByUser(ctx, userUID)
}
