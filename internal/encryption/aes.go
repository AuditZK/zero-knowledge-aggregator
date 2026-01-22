package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

var ErrDecryptionFailed = errors.New("decryption failed: authentication error")

// Service handles AES-256-GCM encryption/decryption
type Service struct {
	key []byte // 32 bytes for AES-256
}

// New creates an encryption service with the given key
func New(key []byte) (*Service, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	return &Service{key: key}, nil
}

// EncryptedData holds the encrypted payload and metadata
type EncryptedData struct {
	Ciphertext string `json:"ciphertext"` // base64
	IV         string `json:"iv"`         // base64
	AuthTag    string `json:"auth_tag"`   // base64
}

// Encrypt encrypts plaintext using AES-256-GCM
func (s *Service) Encrypt(plaintext []byte) (*EncryptedData, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generate iv: %w", err)
	}

	sealed := gcm.Seal(nil, iv, plaintext, nil)

	// GCM appends auth tag at the end (16 bytes)
	tagSize := gcm.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	authTag := sealed[len(sealed)-tagSize:]

	return &EncryptedData{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		IV:         base64.StdEncoding.EncodeToString(iv),
		AuthTag:    base64.StdEncoding.EncodeToString(authTag),
	}, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func (s *Service) Decrypt(data *EncryptedData) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(data.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	iv, err := base64.StdEncoding.DecodeString(data.IV)
	if err != nil {
		return nil, fmt.Errorf("decode iv: %w", err)
	}

	authTag, err := base64.StdEncoding.DecodeString(data.AuthTag)
	if err != nil {
		return nil, fmt.Errorf("decode auth tag: %w", err)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	// Reconstruct sealed data (ciphertext + auth tag)
	sealed := append(ciphertext, authTag...)

	plaintext, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// EncryptString is a convenience method for encrypting strings
func (s *Service) EncryptString(plaintext string) (*EncryptedData, error) {
	return s.Encrypt([]byte(plaintext))
}

// DecryptString is a convenience method for decrypting to string
func (s *Service) DecryptString(data *EncryptedData) (string, error) {
	plaintext, err := s.Decrypt(data)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
