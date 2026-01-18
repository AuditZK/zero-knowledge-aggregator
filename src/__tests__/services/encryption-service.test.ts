import * as crypto from 'node:crypto';
import { EncryptionService } from '../../services/encryption-service';
import { KeyManagementService } from '../../services/key-management.service';

// Mock key management service
const mockDEK = crypto.randomBytes(32);
const mockKeyManagement = {
  getCurrentDEK: jest.fn().mockResolvedValue(mockDEK),
  isSevSnpAvailable: jest.fn().mockResolvedValue(true),
  getCurrentMasterKeyId: jest.fn().mockResolvedValue('abc123def456'),
} as unknown as KeyManagementService;

describe('EncryptionService', () => {
  let service: EncryptionService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new EncryptionService(mockKeyManagement);
  });

  describe('encrypt / decrypt', () => {
    it('should encrypt and decrypt text correctly', async () => {
      const plaintext = 'Hello, World! This is a secret message.';

      const encrypted = await service.encrypt(plaintext);
      const decrypted = await service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt empty string', async () => {
      const plaintext = '';

      const encrypted = await service.encrypt(plaintext);
      const decrypted = await service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt unicode text', async () => {
      const plaintext = 'Bonjour le monde! 你好世界 🔐';

      const encrypted = await service.encrypt(plaintext);
      const decrypted = await service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt large text', async () => {
      const plaintext = 'A'.repeat(100000);

      const encrypted = await service.encrypt(plaintext);
      const decrypted = await service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertext for same plaintext (random IV)', async () => {
      const plaintext = 'Same message';

      const encrypted1 = await service.encrypt(plaintext);
      const encrypted2 = await service.encrypt(plaintext);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should produce hex-encoded output', async () => {
      const plaintext = 'Test';
      const encrypted = await service.encrypt(plaintext);

      expect(encrypted).toMatch(/^[a-f0-9]+$/);
    });

    it('should fail decryption with corrupted ciphertext', async () => {
      const plaintext = 'Secret';
      const encrypted = await service.encrypt(plaintext);

      // Corrupt the ciphertext portion (after IV and tag)
      const corrupted = encrypted.slice(0, -4) + 'ffff';

      await expect(service.decrypt(corrupted)).rejects.toThrow('Decryption failed');
    });

    it('should fail decryption with corrupted auth tag', async () => {
      const plaintext = 'Secret';
      const encrypted = await service.encrypt(plaintext);

      // Corrupt the auth tag (bytes 32-64 of hex string)
      const iv = encrypted.slice(0, 32);
      const tag = encrypted.slice(32, 64);
      const ciphertext = encrypted.slice(64);

      // Flip first byte of tag
      const corruptedTag = (Number.parseInt(tag.slice(0, 2), 16) ^ 0xff)
        .toString(16)
        .padStart(2, '0') + tag.slice(2);

      const corrupted = iv + corruptedTag + ciphertext;

      await expect(service.decrypt(corrupted)).rejects.toThrow('Decryption failed');
    });

    it('should throw when key management fails', async () => {
      mockKeyManagement.getCurrentDEK = jest.fn().mockRejectedValue(
        new Error('Key not available')
      );

      await expect(service.encrypt('test')).rejects.toThrow();
    });
  });

  describe('hash', () => {
    it('should return SHA-256 hash as hex', () => {
      const hash = service.hash('test');

      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should return consistent hash for same input', () => {
      const hash1 = service.hash('test');
      const hash2 = service.hash('test');

      expect(hash1).toBe(hash2);
    });

    it('should return different hash for different input', () => {
      const hash1 = service.hash('test1');
      const hash2 = service.hash('test2');

      expect(hash1).not.toBe(hash2);
    });

    it('should match known SHA-256 hash', () => {
      // Known SHA-256 hash of "test"
      const expected = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
      const hash = service.hash('test');

      expect(hash).toBe(expected);
    });
  });

  describe('createCredentialsHash', () => {
    it('should create hash from credentials', () => {
      const hash = service.createCredentialsHash('apiKey', 'apiSecret', 'passphrase');

      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should create hash without passphrase', () => {
      const hash = service.createCredentialsHash('apiKey', 'apiSecret');

      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce different hash for different credentials', () => {
      const hash1 = service.createCredentialsHash('key1', 'secret1');
      const hash2 = service.createCredentialsHash('key2', 'secret2');

      expect(hash1).not.toBe(hash2);
    });

    it('should produce different hash when passphrase differs', () => {
      const hash1 = service.createCredentialsHash('key', 'secret', 'pass1');
      const hash2 = service.createCredentialsHash('key', 'secret', 'pass2');

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('isHardwareKeyAvailable', () => {
    it('should return true when SEV-SNP is available', async () => {
      mockKeyManagement.isSevSnpAvailable = jest.fn().mockResolvedValue(true);

      const result = await service.isHardwareKeyAvailable();
      expect(result).toBe(true);
    });

    it('should return false when SEV-SNP is not available', async () => {
      mockKeyManagement.isSevSnpAvailable = jest.fn().mockResolvedValue(false);

      const result = await service.isHardwareKeyAvailable();
      expect(result).toBe(false);
    });
  });

  describe('getCurrentMasterKeyId', () => {
    it('should return master key ID from key management', async () => {
      mockKeyManagement.getCurrentMasterKeyId = jest.fn().mockResolvedValue('test-key-id');

      const keyId = await service.getCurrentMasterKeyId();
      expect(keyId).toBe('test-key-id');
    });
  });
});
