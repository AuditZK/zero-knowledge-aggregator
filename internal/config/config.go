package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
)

type Config struct {
	Port          int
	DatabaseURL   string
	EncryptionKey []byte // 32 bytes for AES-256
	Env           string
}

func Load() *Config {
	return &Config{
		Port:          getEnvInt("PORT", 50051),
		DatabaseURL:   getEnv("DATABASE_URL", ""),
		EncryptionKey: getEncryptionKey(),
		Env:           getEnv("ENV", "development"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEncryptionKey() []byte {
	keyHex := os.Getenv("ENCRYPTION_KEY")
	if keyHex != "" {
		key, err := hex.DecodeString(keyHex)
		if err == nil && len(key) == 32 {
			return key
		}
	}

	// Development fallback: generate random key (not for production!)
	key := make([]byte, 32)
	rand.Read(key)
	return key
}
