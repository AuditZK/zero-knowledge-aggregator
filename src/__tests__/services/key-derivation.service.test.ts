import * as crypto from 'node:crypto';
import { KeyDerivationService } from '../../services/key-derivation.service';
import { SevSnpAttestationService } from '../../services/sev-snp-attestation.service';

// Mock the attestation service
const mockAttestationService = {
  getAttestationReport: jest.fn(),
} as unknown as SevSnpAttestationService;

describe('KeyDerivationService', () => {
  let service: KeyDerivationService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new KeyDerivationService(mockAttestationService);
  });

  describe('deriveMasterKey', () => {
    it('should derive master key from valid attestation', async () => {
      const mockMeasurement = crypto.randomBytes(48).toString('hex');
      mockAttestationService.getAttestationReport = jest.fn().mockResolvedValue({
        verified: true,
        sevSnpEnabled: true,
        measurement: mockMeasurement,
        platformVersion: 'test-platform-v1',
      });

      const masterKey = await service.deriveMasterKey();

      expect(masterKey).toBeInstanceOf(Buffer);
      expect(masterKey.length).toBe(32); // 256 bits
      expect(mockAttestationService.getAttestationReport).toHaveBeenCalledTimes(1);
    });

    it('should derive consistent key for same measurement', async () => {
      const mockMeasurement = crypto.randomBytes(48).toString('hex');
      mockAttestationService.getAttestationReport = jest.fn().mockResolvedValue({
        verified: true,
        sevSnpEnabled: true,
        measurement: mockMeasurement,
        platformVersion: 'test-platform-v1',
      });

      const key1 = await service.deriveMasterKey();
      const key2 = await service.deriveMasterKey();

      expect(key1.equals(key2)).toBe(true);
    });

    it('should throw error when attestation not verified', async () => {
      mockAttestationService.getAttestationReport = jest.fn().mockResolvedValue({
        verified: false,
        sevSnpEnabled: false,
        measurement: null,
      });

      await expect(service.deriveMasterKey()).rejects.toThrow(
        'SEV-SNP attestation verification failed'
      );
    });

    it('should throw error when measurement is missing', async () => {
      mockAttestationService.getAttestationReport = jest.fn().mockResolvedValue({
        verified: true,
        sevSnpEnabled: true,
        measurement: null,
      });

      await expect(service.deriveMasterKey()).rejects.toThrow(
        'SEV-SNP attestation verification failed'
      );
    });
  });

  describe('generateDataEncryptionKey', () => {
    it('should generate 256-bit random key', () => {
      const dek = service.generateDataEncryptionKey();

      expect(dek).toBeInstanceOf(Buffer);
      expect(dek.length).toBe(32);
    });

    it('should generate unique keys each time', () => {
      const dek1 = service.generateDataEncryptionKey();
      const dek2 = service.generateDataEncryptionKey();

      expect(dek1.equals(dek2)).toBe(false);
    });
  });

  describe('wrapKey / unwrapKey', () => {
    const masterKey = crypto.randomBytes(32);
    const dek = crypto.randomBytes(32);

    it('should wrap and unwrap key correctly', () => {
      const wrapped = service.wrapKey(dek, masterKey);

      expect(wrapped).toHaveProperty('encryptedDEK');
      expect(wrapped).toHaveProperty('iv');
      expect(wrapped).toHaveProperty('authTag');
      expect(wrapped).toHaveProperty('keyVersion', 'v1');

      const unwrapped = service.unwrapKey(wrapped, masterKey);
      expect(unwrapped.equals(dek)).toBe(true);
    });

    it('should produce different ciphertext for same key (random IV)', () => {
      const wrapped1 = service.wrapKey(dek, masterKey);
      const wrapped2 = service.wrapKey(dek, masterKey);

      expect(wrapped1.encryptedDEK).not.toBe(wrapped2.encryptedDEK);
      expect(wrapped1.iv).not.toBe(wrapped2.iv);
    });

    it('should fail to unwrap with wrong master key', () => {
      const wrapped = service.wrapKey(dek, masterKey);
      const wrongMasterKey = crypto.randomBytes(32);

      expect(() => service.unwrapKey(wrapped, wrongMasterKey)).toThrow(
        'Key unwrapping failed'
      );
    });

    it('should fail to unwrap if authTag is tampered', () => {
      const wrapped = service.wrapKey(dek, masterKey);
      const tamperedAuthTag = Buffer.from(wrapped.authTag, 'base64');
      tamperedAuthTag.writeUInt8(tamperedAuthTag.readUInt8(0) ^ 0xff, 0); // Flip bits

      const tampered = {
        ...wrapped,
        authTag: tamperedAuthTag.toString('base64'),
      };

      expect(() => service.unwrapKey(tampered, masterKey)).toThrow(
        'Key unwrapping failed'
      );
    });

    it('should fail to unwrap if ciphertext is tampered', () => {
      const wrapped = service.wrapKey(dek, masterKey);
      const tamperedCiphertext = Buffer.from(wrapped.encryptedDEK, 'base64');
      tamperedCiphertext.writeUInt8(tamperedCiphertext.readUInt8(0) ^ 0xff, 0);

      const tampered = {
        ...wrapped,
        encryptedDEK: tamperedCiphertext.toString('base64'),
      };

      expect(() => service.unwrapKey(tampered, masterKey)).toThrow(
        'Key unwrapping failed'
      );
    });
  });

  describe('getMasterKeyId', () => {
    it('should return 16-character hex string', () => {
      const masterKey = crypto.randomBytes(32);
      const keyId = service.getMasterKeyId(masterKey);

      expect(keyId).toMatch(/^[a-f0-9]{16}$/);
    });

    it('should return consistent ID for same key', () => {
      const masterKey = crypto.randomBytes(32);
      const id1 = service.getMasterKeyId(masterKey);
      const id2 = service.getMasterKeyId(masterKey);

      expect(id1).toBe(id2);
    });

    it('should return different IDs for different keys', () => {
      const key1 = crypto.randomBytes(32);
      const key2 = crypto.randomBytes(32);

      const id1 = service.getMasterKeyId(key1);
      const id2 = service.getMasterKeyId(key2);

      expect(id1).not.toBe(id2);
    });
  });

  describe('isSevSnpAvailable', () => {
    it('should return true when attestation is verified and enabled', async () => {
      mockAttestationService.getAttestationReport = jest.fn().mockResolvedValue({
        verified: true,
        sevSnpEnabled: true,
      });

      const result = await service.isSevSnpAvailable();
      expect(result).toBe(true);
    });

    it('should return false when attestation fails', async () => {
      mockAttestationService.getAttestationReport = jest.fn().mockResolvedValue({
        verified: false,
        sevSnpEnabled: false,
      });

      const result = await service.isSevSnpAvailable();
      expect(result).toBe(false);
    });

    it('should return false when service throws', async () => {
      mockAttestationService.getAttestationReport = jest.fn().mockRejectedValue(
        new Error('Attestation service unavailable')
      );

      const result = await service.isSevSnpAvailable();
      expect(result).toBe(false);
    });
  });
});
