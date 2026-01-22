package encryption

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

const (
	sevGuestDevice = "/dev/sev-guest"
	masterKeySize  = 32
)

// KeyDerivationService derives master keys from hardware measurements
type KeyDerivationService struct {
	masterKey []byte
	isHardware bool
}

// NewKeyDerivationService creates a new key derivation service
func NewKeyDerivationService() (*KeyDerivationService, error) {
	svc := &KeyDerivationService{}
	if err := svc.deriveMasterKey(); err != nil {
		return nil, err
	}
	return svc, nil
}

// deriveMasterKey derives the master key from SEV-SNP or generates a dev key
func (s *KeyDerivationService) deriveMasterKey() error {
	// Try to read from SEV-SNP hardware
	measurement, err := s.getSEVMeasurement()
	if err != nil {
		// Fallback to development mode
		s.masterKey = make([]byte, masterKeySize)
		if _, err := rand.Read(s.masterKey); err != nil {
			return fmt.Errorf("generate dev key: %w", err)
		}
		s.isHardware = false
		return nil
	}

	// Derive master key using HKDF
	hash := sha256.New
	reader := hkdf.New(hash, measurement, nil, []byte("enclave-master-key-v1"))

	s.masterKey = make([]byte, masterKeySize)
	if _, err := io.ReadFull(reader, s.masterKey); err != nil {
		return fmt.Errorf("derive master key: %w", err)
	}

	s.isHardware = true
	return nil
}

// getSEVMeasurement reads the SEV-SNP measurement from hardware
func (s *KeyDerivationService) getSEVMeasurement() ([]byte, error) {
	// Check if running in SEV-SNP environment
	if _, err := os.Stat(sevGuestDevice); os.IsNotExist(err) {
		return nil, fmt.Errorf("SEV-SNP not available")
	}

	// Read measurement from SEV guest device
	// In production, this would use the sev-guest ioctl interface
	// For now, we read a simulated measurement
	file, err := os.Open(sevGuestDevice)
	if err != nil {
		return nil, fmt.Errorf("open sev device: %w", err)
	}
	defer file.Close()

	measurement := make([]byte, 48) // SEV-SNP measurement is 384 bits
	if _, err := io.ReadFull(file, measurement); err != nil {
		return nil, fmt.Errorf("read measurement: %w", err)
	}

	return measurement, nil
}

// WrapKey encrypts a DEK with the master key
func (s *KeyDerivationService) WrapKey(dek []byte) (*EncryptedData, error) {
	svc, err := New(s.masterKey)
	if err != nil {
		return nil, err
	}
	return svc.Encrypt(dek)
}

// UnwrapKey decrypts a DEK with the master key
func (s *KeyDerivationService) UnwrapKey(wrapped *EncryptedData) ([]byte, error) {
	svc, err := New(s.masterKey)
	if err != nil {
		return nil, err
	}
	return svc.Decrypt(wrapped)
}

// IsHardwareKey returns true if using hardware-derived key
func (s *KeyDerivationService) IsHardwareKey() bool {
	return s.isHardware
}

// GetMasterKeyID returns a hash of the master key for identification
func (s *KeyDerivationService) GetMasterKeyID() string {
	hash := sha256.Sum256(s.masterKey)
	return fmt.Sprintf("%x", hash[:8])
}
