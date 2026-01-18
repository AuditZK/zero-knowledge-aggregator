import { DEKRepository } from '../../repositories/dek-repository';
import { PrismaClient } from '@prisma/client';

// Mock the logger
jest.mock('../../utils/secure-enclave-logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
  extractErrorMessage: (error: unknown) => error instanceof Error ? error.message : String(error),
}));

describe('DEKRepository', () => {
  let repository: DEKRepository;
  let mockPrisma: jest.Mocked<PrismaClient>;

  const mockDEK = {
    id: 'dek_123',
    encryptedDEK: 'encrypted_dek_base64',
    iv: 'iv_base64',
    authTag: 'auth_tag_base64',
    keyVersion: 'v1',
    masterKeyId: 'master_key_001',
    isActive: true,
    rotatedAt: null,
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01'),
  };

  beforeEach(() => {
    mockPrisma = {
      dataEncryptionKey: {
        findFirst: jest.fn(),
        findMany: jest.fn(),
        create: jest.fn(),
        updateMany: jest.fn(),
        deleteMany: jest.fn(),
        count: jest.fn(),
      },
    } as unknown as jest.Mocked<PrismaClient>;

    repository = new DEKRepository(mockPrisma);
  });

  describe('getActiveDEK', () => {
    it('should return active DEK when found', async () => {
      (mockPrisma.dataEncryptionKey.findFirst as jest.Mock).mockResolvedValue(mockDEK);

      const result = await repository.getActiveDEK();

      expect(result).not.toBeNull();
      expect(result!.id).toBe('dek_123');
      expect(result!.isActive).toBe(true);
      expect(mockPrisma.dataEncryptionKey.findFirst).toHaveBeenCalledWith({
        where: { isActive: true },
      });
    });

    it('should return null when no active DEK exists', async () => {
      (mockPrisma.dataEncryptionKey.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await repository.getActiveDEK();

      expect(result).toBeNull();
    });

    it('should propagate database errors', async () => {
      (mockPrisma.dataEncryptionKey.findFirst as jest.Mock).mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(repository.getActiveDEK()).rejects.toThrow('Database connection failed');
    });
  });

  describe('createDEK', () => {
    const newDEKData = {
      encryptedDEK: 'new_encrypted_dek',
      iv: 'new_iv',
      authTag: 'new_auth_tag',
      keyVersion: 'v2',
      masterKeyId: 'master_key_002',
    };

    it('should create new DEK and deactivate existing ones', async () => {
      (mockPrisma.dataEncryptionKey.updateMany as jest.Mock).mockResolvedValue({ count: 1 });
      (mockPrisma.dataEncryptionKey.create as jest.Mock).mockResolvedValue({
        ...mockDEK,
        ...newDEKData,
        id: 'dek_new',
      });

      const result = await repository.createDEK(newDEKData);

      expect(mockPrisma.dataEncryptionKey.updateMany).toHaveBeenCalledWith({
        where: { isActive: true },
        data: {
          isActive: false,
          rotatedAt: expect.any(Date),
        },
      });
      expect(result.keyVersion).toBe('v2');
      expect(result.masterKeyId).toBe('master_key_002');
    });

    it('should set isActive to true for new DEK', async () => {
      (mockPrisma.dataEncryptionKey.updateMany as jest.Mock).mockResolvedValue({ count: 0 });
      (mockPrisma.dataEncryptionKey.create as jest.Mock).mockResolvedValue({
        ...mockDEK,
        ...newDEKData,
        isActive: true,
      });

      const result = await repository.createDEK(newDEKData);

      expect(mockPrisma.dataEncryptionKey.create).toHaveBeenCalledWith({
        data: {
          ...newDEKData,
          isActive: true,
        },
      });
      expect(result.isActive).toBe(true);
    });

    it('should propagate creation errors', async () => {
      (mockPrisma.dataEncryptionKey.updateMany as jest.Mock).mockResolvedValue({ count: 0 });
      (mockPrisma.dataEncryptionKey.create as jest.Mock).mockRejectedValue(
        new Error('Create failed')
      );

      await expect(repository.createDEK(newDEKData)).rejects.toThrow('Create failed');
    });
  });

  describe('rotateDEK', () => {
    it('should create new DEK using createDEK method', async () => {
      const newDEKData = {
        encryptedDEK: 'rotated_dek',
        iv: 'rotated_iv',
        authTag: 'rotated_auth_tag',
        keyVersion: 'v3',
        masterKeyId: 'master_key_003',
      };

      (mockPrisma.dataEncryptionKey.updateMany as jest.Mock).mockResolvedValue({ count: 1 });
      (mockPrisma.dataEncryptionKey.create as jest.Mock).mockResolvedValue({
        ...mockDEK,
        ...newDEKData,
        id: 'dek_rotated',
      });

      const result = await repository.rotateDEK(newDEKData);

      expect(result.keyVersion).toBe('v3');
      expect(mockPrisma.dataEncryptionKey.updateMany).toHaveBeenCalled();
    });
  });

  describe('getAllDEKs', () => {
    it('should return all DEKs ordered by creation date', async () => {
      const allDEKs = [
        mockDEK,
        { ...mockDEK, id: 'dek_old', isActive: false, rotatedAt: new Date('2023-12-01') },
      ];
      (mockPrisma.dataEncryptionKey.findMany as jest.Mock).mockResolvedValue(allDEKs);

      const result = await repository.getAllDEKs();

      expect(result.length).toBe(2);
      expect(mockPrisma.dataEncryptionKey.findMany).toHaveBeenCalledWith({
        orderBy: { createdAt: 'desc' },
      });
    });

    it('should return empty array when no DEKs exist', async () => {
      (mockPrisma.dataEncryptionKey.findMany as jest.Mock).mockResolvedValue([]);

      const result = await repository.getAllDEKs();

      expect(result).toEqual([]);
    });
  });

  describe('getDEKsByMasterKeyId', () => {
    it('should return DEKs for specific master key', async () => {
      const deksForMasterKey = [
        mockDEK,
        { ...mockDEK, id: 'dek_456', keyVersion: 'v1.1' },
      ];
      (mockPrisma.dataEncryptionKey.findMany as jest.Mock).mockResolvedValue(deksForMasterKey);

      const result = await repository.getDEKsByMasterKeyId('master_key_001');

      expect(result.length).toBe(2);
      expect(mockPrisma.dataEncryptionKey.findMany).toHaveBeenCalledWith({
        where: { masterKeyId: 'master_key_001' },
        orderBy: { createdAt: 'desc' },
      });
    });

    it('should return empty array for unknown master key', async () => {
      (mockPrisma.dataEncryptionKey.findMany as jest.Mock).mockResolvedValue([]);

      const result = await repository.getDEKsByMasterKeyId('unknown_master_key');

      expect(result).toEqual([]);
    });
  });

  describe('deleteInactiveDEKs', () => {
    it('should delete inactive DEKs older than specified date', async () => {
      (mockPrisma.dataEncryptionKey.deleteMany as jest.Mock).mockResolvedValue({ count: 5 });

      const olderThan = new Date('2024-01-01');
      const result = await repository.deleteInactiveDEKs(olderThan);

      expect(result).toBe(5);
      expect(mockPrisma.dataEncryptionKey.deleteMany).toHaveBeenCalledWith({
        where: {
          isActive: false,
          rotatedAt: {
            lt: olderThan,
          },
        },
      });
    });

    it('should return 0 when no DEKs match criteria', async () => {
      (mockPrisma.dataEncryptionKey.deleteMany as jest.Mock).mockResolvedValue({ count: 0 });

      const result = await repository.deleteInactiveDEKs(new Date());

      expect(result).toBe(0);
    });
  });

  describe('hasActiveDEK', () => {
    it('should return true when active DEK exists', async () => {
      (mockPrisma.dataEncryptionKey.count as jest.Mock).mockResolvedValue(1);

      const result = await repository.hasActiveDEK();

      expect(result).toBe(true);
      expect(mockPrisma.dataEncryptionKey.count).toHaveBeenCalledWith({
        where: { isActive: true },
      });
    });

    it('should return false when no active DEK exists', async () => {
      (mockPrisma.dataEncryptionKey.count as jest.Mock).mockResolvedValue(0);

      const result = await repository.hasActiveDEK();

      expect(result).toBe(false);
    });

    it('should propagate database errors', async () => {
      (mockPrisma.dataEncryptionKey.count as jest.Mock).mockRejectedValue(
        new Error('Count failed')
      );

      await expect(repository.hasActiveDEK()).rejects.toThrow('Count failed');
    });
  });
});
