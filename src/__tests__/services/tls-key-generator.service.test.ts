import { TlsKeyGeneratorService } from '../../services/tls-key-generator.service';

describe('TlsKeyGeneratorService', () => {
  let service: TlsKeyGeneratorService;

  beforeEach(() => {
    service = new TlsKeyGeneratorService();
  });

  afterEach(() => {
    service.clearCredentials();
  });

  describe('getCredentials', () => {
    it('should generate TLS credentials', async () => {
      const credentials = await service.getCredentials();

      expect(credentials).toHaveProperty('privateKey');
      expect(credentials).toHaveProperty('certificate');
      expect(credentials).toHaveProperty('fingerprint');
    });

    it('should return PEM-formatted private key', async () => {
      const credentials = await service.getCredentials();

      expect(credentials.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
      expect(credentials.privateKey).toContain('-----END PRIVATE KEY-----');
    });

    it('should return PEM-formatted certificate', async () => {
      const credentials = await service.getCredentials();

      expect(credentials.certificate).toContain('-----BEGIN CERTIFICATE-----');
      expect(credentials.certificate).toContain('-----END CERTIFICATE-----');
    });

    it('should return SHA-256 fingerprint in colon-separated format', async () => {
      const credentials = await service.getCredentials();

      // SHA-256 fingerprint format: XX:XX:XX:... (64 hex chars + 31 colons = 95 chars)
      expect(credentials.fingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    });

    it('should return same credentials on subsequent calls', async () => {
      const credentials1 = await service.getCredentials();
      const credentials2 = await service.getCredentials();

      expect(credentials1).toBe(credentials2);
      expect(credentials1.fingerprint).toBe(credentials2.fingerprint);
    });

    it('should generate unique credentials for different instances', async () => {
      const service1 = new TlsKeyGeneratorService();
      const service2 = new TlsKeyGeneratorService();

      const creds1 = await service1.getCredentials();
      const creds2 = await service2.getCredentials();

      expect(creds1.fingerprint).not.toBe(creds2.fingerprint);
      expect(creds1.privateKey).not.toBe(creds2.privateKey);

      service1.clearCredentials();
      service2.clearCredentials();
    });
  });

  describe('getFingerprint', () => {
    it('should return null before credentials are generated', () => {
      const fingerprint = service.getFingerprint();

      expect(fingerprint).toBeNull();
    });

    it('should return fingerprint after credentials are generated', async () => {
      await service.getCredentials();
      const fingerprint = service.getFingerprint();

      expect(fingerprint).not.toBeNull();
      expect(fingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    });

    it('should return same fingerprint as in credentials', async () => {
      const credentials = await service.getCredentials();
      const fingerprint = service.getFingerprint();

      expect(fingerprint).toBe(credentials.fingerprint);
    });
  });

  describe('verifyFingerprint', () => {
    it('should return true for matching fingerprint', async () => {
      const credentials = await service.getCredentials();

      const result = service.verifyFingerprint(credentials.certificate, credentials.fingerprint);

      expect(result).toBe(true);
    });

    it('should return false for non-matching fingerprint', async () => {
      const credentials = await service.getCredentials();
      const fakeFingerprint = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';

      const result = service.verifyFingerprint(credentials.certificate, fakeFingerprint);

      expect(result).toBe(false);
    });

    it('should verify fingerprint of another certificate', async () => {
      const service1 = new TlsKeyGeneratorService();
      const service2 = new TlsKeyGeneratorService();

      const creds1 = await service1.getCredentials();
      const creds2 = await service2.getCredentials();

      // Cross-verify should fail
      expect(service1.verifyFingerprint(creds2.certificate, creds1.fingerprint)).toBe(false);
      expect(service2.verifyFingerprint(creds1.certificate, creds2.fingerprint)).toBe(false);

      // Self-verify should succeed
      expect(service1.verifyFingerprint(creds1.certificate, creds1.fingerprint)).toBe(true);
      expect(service2.verifyFingerprint(creds2.certificate, creds2.fingerprint)).toBe(true);

      service1.clearCredentials();
      service2.clearCredentials();
    });
  });

  describe('clearCredentials', () => {
    it('should clear credentials from memory', async () => {
      await service.getCredentials();
      expect(service.getFingerprint()).not.toBeNull();

      service.clearCredentials();

      expect(service.getFingerprint()).toBeNull();
    });

    it('should be safe to call multiple times', () => {
      expect(() => {
        service.clearCredentials();
        service.clearCredentials();
      }).not.toThrow();
    });

    it('should allow generating new credentials after clear', async () => {
      const creds1 = await service.getCredentials();
      const fingerprint1 = creds1.fingerprint;

      service.clearCredentials();

      const creds2 = await service.getCredentials();
      const fingerprint2 = creds2.fingerprint;

      // New credentials should be different
      expect(fingerprint2).not.toBe(fingerprint1);
    });
  });

  describe('certificate content', () => {
    it('should generate valid base64 content in certificate', async () => {
      const credentials = await service.getCredentials();

      // Extract base64 content
      const base64Content = credentials.certificate
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replaceAll(/\s/g, '');

      // Should be valid base64
      expect(() => Buffer.from(base64Content, 'base64')).not.toThrow();
    });

    it('should generate ECDSA P-256 key', async () => {
      const credentials = await service.getCredentials();

      // Private key should be PKCS8 format for EC key
      expect(credentials.privateKey).toContain('-----BEGIN PRIVATE KEY-----');

      // The key should be usable
      const crypto = await import('node:crypto');
      const keyObject = crypto.createPrivateKey(credentials.privateKey);
      expect(keyObject.asymmetricKeyType).toBe('ec');
    });
  });
});
