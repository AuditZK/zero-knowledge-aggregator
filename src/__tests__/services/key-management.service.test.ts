import * as crypto from 'node:crypto';
import { KeyManagementService } from '../../services/key-management.service';
import { KeyDerivationService } from '../../services/key-derivation.service';
import { DEKRepository } from '../../repositories/dek-repository';

describe('KeyManagementService', () => {
  let service: KeyManagementService;
  let mockKeyDerivation: jest.Mocked<KeyDerivationService>;
  let mockDekRepo: jest.Mocked<DEKRepository>;

  const mockMasterKey = crypto.randomBytes(32);
  const mockMasterKeyId = 'abc123def456';
  const mockDEK = crypto.randomBytes(32);
  const mockWrappedDEK = {
    id: 'dek-1',
    encryptedDEK: 'encrypted-data',
    iv: 'initialization-vector',
    authTag: 'auth-tag',
    keyVersion: 'v1',
    masterKeyId: mockMasterKeyId,
    isActive: true,
    createdAt: new Date(),
  };

  beforeEach(() => {
    jest.clearAllMocks();

    mockKeyDerivation = {
      deriveMasterKey: jest.fn().mockResolvedValue(mockMasterKey),
      getMasterKeyId: jest.fn().mockReturnValue(mockMasterKeyId),
      generateDataEncryptionKey: jest.fn().mockReturnValue(mockDEK),
      wrapKey: jest.fn().mockReturnValue({
        encryptedDEK: 'new-encrypted',
        iv: 'new-iv',
        authTag: 'new-tag',
        keyVersion: 'v1',
      }),
      unwrapKey: jest.fn().mockReturnValue(mockDEK),
      isSevSnpAvailable: jest.fn().mockResolvedValue(true),
    } as unknown as jest.Mocked<KeyDerivationService>;

    mockDekRepo = {
      getActiveDEK: jest.fn().mockResolvedValue(mockWrappedDEK),
      createDEK: jest.fn().mockResolvedValue(mockWrappedDEK),
      rotateDEK: jest.fn().mockResolvedValue(mockWrappedDEK),
      hasActiveDEK: jest.fn().mockResolvedValue(true),
    } as unknown as jest.Mocked<DEKRepository>;

    service = new KeyManagementService(mockKeyDerivation, mockDekRepo);
  });

  describe('getCurrentDEK', () => {
    it('should return cached DEK on subsequent calls', async () => {
      const dek1 = await service.getCurrentDEK();
      const dek2 = await service.getCurrentDEK();

      expect(dek1).toBe(dek2);
      // Should only derive master key once
      expect(mockKeyDerivation.deriveMasterKey).toHaveBeenCalledTimes(1);
    });

    it('should initialize new DEK when none exists', async () => {
      mockDekRepo.getActiveDEK = jest.fn().mockResolvedValue(null);

      const dek = await service.getCurrentDEK();

      expect(dek).toEqual(mockDEK);
      expect(mockKeyDerivation.generateDataEncryptionKey).toHaveBeenCalled();
      expect(mockDekRepo.createDEK).toHaveBeenCalled();
    });

    it('should unwrap existing DEK when master key matches', async () => {
      const dek = await service.getCurrentDEK();

      expect(dek).toEqual(mockDEK);
      expect(mockKeyDerivation.unwrapKey).toHaveBeenCalledWith(
        mockWrappedDEK,
        mockMasterKey
      );
    });

    it('should throw when master key ID mismatch', async () => {
      mockKeyDerivation.getMasterKeyId = jest.fn().mockReturnValue('different-key-id');

      await expect(service.getCurrentDEK()).rejects.toThrow(
        'Master key mismatch detected'
      );
    });
  });

  describe('rotateDEK', () => {
    it('should generate new DEK and wrap it', async () => {
      const newDEK = await service.rotateDEK();

      expect(newDEK).toEqual(mockDEK);
      expect(mockKeyDerivation.generateDataEncryptionKey).toHaveBeenCalled();
      expect(mockKeyDerivation.wrapKey).toHaveBeenCalledWith(mockDEK, mockMasterKey);
      expect(mockDekRepo.rotateDEK).toHaveBeenCalled();
    });

    it('should clear cache after rotation', async () => {
      // First call to cache
      await service.getCurrentDEK();
      expect(mockKeyDerivation.deriveMasterKey).toHaveBeenCalledTimes(1);

      // Rotate
      await service.rotateDEK();

      // Clear mocks to track new calls
      mockKeyDerivation.deriveMasterKey.mockClear();
      mockKeyDerivation.unwrapKey.mockClear();

      // Next call should re-derive
      await service.getCurrentDEK();
      expect(mockKeyDerivation.deriveMasterKey).toHaveBeenCalledTimes(1);
    });
  });

  describe('migrateDEKToNewMasterKey', () => {
    it('should re-wrap DEK with new master key', async () => {
      const oldMasterKey = crypto.randomBytes(32);
      const newMasterKey = crypto.randomBytes(32);
      const newMasterKeyId = 'new-key-id';

      mockKeyDerivation.deriveMasterKey = jest.fn().mockResolvedValue(newMasterKey);
      mockKeyDerivation.getMasterKeyId = jest.fn().mockReturnValue(newMasterKeyId);

      const dek = await service.migrateDEKToNewMasterKey(oldMasterKey);

      expect(dek).toEqual(mockDEK);
      expect(mockKeyDerivation.unwrapKey).toHaveBeenCalledWith(
        mockWrappedDEK,
        oldMasterKey
      );
      expect(mockKeyDerivation.wrapKey).toHaveBeenCalledWith(mockDEK, newMasterKey);
      expect(mockDekRepo.rotateDEK).toHaveBeenCalled();
    });

    it('should throw when no active DEK exists', async () => {
      mockDekRepo.getActiveDEK = jest.fn().mockResolvedValue(null);

      const oldMasterKey = crypto.randomBytes(32);

      await expect(service.migrateDEKToNewMasterKey(oldMasterKey)).rejects.toThrow(
        'No active DEK found for migration'
      );
    });
  });

  describe('needsInitialization', () => {
    it('should return true when no active DEK', async () => {
      mockDekRepo.hasActiveDEK = jest.fn().mockResolvedValue(false);

      const result = await service.needsInitialization();
      expect(result).toBe(true);
    });

    it('should return false when active DEK exists', async () => {
      mockDekRepo.hasActiveDEK = jest.fn().mockResolvedValue(true);

      const result = await service.needsInitialization();
      expect(result).toBe(false);
    });
  });

  describe('hasRequiredMigration', () => {
    it('should return false when master key matches', async () => {
      const result = await service.hasRequiredMigration();
      expect(result).toBe(false);
    });

    it('should return true when master key mismatch', async () => {
      mockKeyDerivation.getMasterKeyId = jest.fn().mockReturnValue('different-id');

      const result = await service.hasRequiredMigration();
      expect(result).toBe(true);
    });

    it('should return false when no active DEK', async () => {
      mockDekRepo.getActiveDEK = jest.fn().mockResolvedValue(null);

      const result = await service.hasRequiredMigration();
      expect(result).toBe(false);
    });
  });

  describe('clearCache', () => {
    it('should force re-derivation on next getCurrentDEK call', async () => {
      await service.getCurrentDEK();
      expect(mockKeyDerivation.deriveMasterKey).toHaveBeenCalledTimes(1);

      service.clearCache();
      mockKeyDerivation.deriveMasterKey.mockClear();

      await service.getCurrentDEK();
      expect(mockKeyDerivation.deriveMasterKey).toHaveBeenCalledTimes(1);
    });
  });

  describe('isSevSnpAvailable', () => {
    it('should delegate to key derivation service', async () => {
      mockKeyDerivation.isSevSnpAvailable = jest.fn().mockResolvedValue(true);

      const result = await service.isSevSnpAvailable();

      expect(result).toBe(true);
      expect(mockKeyDerivation.isSevSnpAvailable).toHaveBeenCalled();
    });
  });

  describe('getCurrentMasterKeyId', () => {
    it('should derive and return master key ID', async () => {
      const keyId = await service.getCurrentMasterKeyId();

      expect(keyId).toBe(mockMasterKeyId);
      expect(mockKeyDerivation.deriveMasterKey).toHaveBeenCalled();
      expect(mockKeyDerivation.getMasterKeyId).toHaveBeenCalledWith(mockMasterKey);
    });
  });
});
