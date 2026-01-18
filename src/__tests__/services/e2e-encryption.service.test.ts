import { E2EEncryptionService } from '../../services/e2e-encryption.service';

describe('E2EEncryptionService', () => {
  let service: E2EEncryptionService;

  beforeEach(async () => {
    service = new E2EEncryptionService();
    await service.initialize();
  });

  describe('initialize', () => {
    it('should generate ECDH key pair', async () => {
      const newService = new E2EEncryptionService();
      await newService.initialize();

      const publicKey = newService.getPublicKey();
      expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(publicKey).toContain('-----END PUBLIC KEY-----');
    });
  });

  describe('getPublicKey', () => {
    it('should return PEM-encoded public key', () => {
      const publicKey = service.getPublicKey();

      expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(typeof publicKey).toBe('string');
    });

    it('should throw if not initialized', () => {
      const uninitService = new E2EEncryptionService();

      expect(() => uninitService.getPublicKey()).toThrow('E2E encryption not initialized');
    });
  });

  describe('getPublicKeyFingerprint', () => {
    it('should return SHA256 fingerprint as hex string', () => {
      const fingerprint = service.getPublicKeyFingerprint();

      expect(fingerprint).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should return consistent fingerprint', () => {
      const fp1 = service.getPublicKeyFingerprint();
      const fp2 = service.getPublicKeyFingerprint();

      expect(fp1).toBe(fp2);
    });

    it('should throw if not initialized', () => {
      const uninitService = new E2EEncryptionService();

      expect(() => uninitService.getPublicKeyFingerprint()).toThrow('E2E encryption not initialized');
    });
  });

  describe('encrypt', () => {
    it('should return encrypted data structure', () => {
      const plaintext = 'Hello, World!';
      const encrypted = service.encrypt(plaintext);

      expect(encrypted).toHaveProperty('ephemeralPublicKey');
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted).toHaveProperty('ciphertext');
      expect(encrypted).toHaveProperty('tag');
    });

    it('should produce different ciphertext for same plaintext (random IV)', () => {
      const plaintext = 'Same message';
      const encrypted1 = service.encrypt(plaintext);
      const encrypted2 = service.encrypt(plaintext);

      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
    });

    it('should throw if not initialized', () => {
      const uninitService = new E2EEncryptionService();

      expect(() => uninitService.encrypt('test')).toThrow('E2E encryption not initialized');
    });
  });

  describe('decrypt', () => {
    it('should decrypt encrypted data correctly', () => {
      const plaintext = 'Secret API Key: sk_test_12345';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should decrypt empty string', () => {
      const plaintext = '';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe('');
    });

    it('should decrypt unicode content', () => {
      const plaintext = '你好世界 🔐 مرحبا';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should decrypt large content', () => {
      const plaintext = 'A'.repeat(10000);
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should throw on tampered ciphertext', () => {
      const encrypted = service.encrypt('test');
      // Tamper with ciphertext
      const tamperedCiphertext = encrypted.ciphertext.slice(0, -2) + '00';

      expect(() => service.decrypt({
        ...encrypted,
        ciphertext: tamperedCiphertext,
      })).toThrow('Failed to decrypt credentials');
    });

    it('should throw on tampered auth tag', () => {
      const encrypted = service.encrypt('test');
      // Tamper with auth tag by completely replacing it with invalid data
      const tamperedTag = 'ff'.repeat(16); // Replace with all 0xff bytes

      expect(() => service.decrypt({
        ...encrypted,
        tag: tamperedTag,
      })).toThrow('Failed to decrypt credentials');
    });

    it('should throw on invalid ephemeral public key', () => {
      const encrypted = service.encrypt('test');

      expect(() => service.decrypt({
        ...encrypted,
        ephemeralPublicKey: 'invalid-key',
      })).toThrow('Failed to decrypt credentials');
    });

    it('should throw if not initialized', () => {
      const uninitService = new E2EEncryptionService();
      const encrypted = service.encrypt('test');

      expect(() => uninitService.decrypt(encrypted)).toThrow('E2E encryption not initialized');
    });
  });

  describe('end-to-end roundtrip', () => {
    it('should encrypt and decrypt JSON credentials', () => {
      const credentials = {
        apiKey: 'pk_live_abc123',
        apiSecret: 'sk_live_xyz789',
        passphrase: 'my-secret-passphrase',
      };

      const plaintext = JSON.stringify(credentials);
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);
      const recovered = JSON.parse(decrypted);

      expect(recovered).toEqual(credentials);
    });
  });
});
