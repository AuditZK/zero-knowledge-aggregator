package encryption

import (
	"crypto/rand"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	svc, err := New(key)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	plaintext := "my_api_secret_key_123"

	encrypted, err := svc.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if encrypted.Ciphertext == plaintext {
		t.Error("ciphertext should not equal plaintext")
	}

	decrypted, err := svc.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() = %v, want %v", decrypted, plaintext)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	svc1, _ := New(key1)
	svc2, _ := New(key2)

	encrypted, _ := svc1.EncryptString("secret")

	_, err := svc2.DecryptString(encrypted)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestInvalidKeyLength(t *testing.T) {
	_, err := New([]byte("short"))
	if err == nil {
		t.Error("expected error for short key")
	}
}
