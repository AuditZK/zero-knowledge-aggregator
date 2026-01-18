import { SyncStatusRepository } from '../../core/repositories/sync-status-repository';
import { PrismaClient, SyncStatusEnum } from '@prisma/client';

// Mock the logger
jest.mock('../../utils/secure-enclave-logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

describe('SyncStatusRepository', () => {
  let repository: SyncStatusRepository;
  let mockPrisma: jest.Mocked<PrismaClient>;

  const mockSyncStatus = {
    id: 'sync_123',
    userUid: 'user_abc',
    exchange: 'binance',
    lastSyncTime: new Date('2024-01-15'),
    status: SyncStatusEnum.completed,
    totalTrades: 100,
    errorMessage: null,
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-15'),
  };

  beforeEach(() => {
    mockPrisma = {
      syncStatus: {
        upsert: jest.fn(),
        findUnique: jest.fn(),
        findMany: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
      },
    } as unknown as jest.Mocked<PrismaClient>;

    repository = new SyncStatusRepository(mockPrisma);
  });

  describe('upsertSyncStatus', () => {
    it('should create or update sync status', async () => {
      (mockPrisma.syncStatus.upsert as jest.Mock).mockResolvedValue(mockSyncStatus);

      const input = {
        userUid: 'user_abc',
        exchange: 'binance',
        lastSyncTime: new Date('2024-01-15'),
        status: 'completed' as const,
        totalTrades: 100,
        errorMessage: undefined,
      };

      const result = await repository.upsertSyncStatus(input);

      expect(mockPrisma.syncStatus.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            userUid_exchange: {
              userUid: 'user_abc',
              exchange: 'binance',
            },
          },
        })
      );
      expect(result.status).toBe('completed');
      expect(result.totalTrades).toBe(100);
    });
  });

  describe('getSyncStatus', () => {
    it('should return sync status when found', async () => {
      (mockPrisma.syncStatus.findUnique as jest.Mock).mockResolvedValue(mockSyncStatus);

      const result = await repository.getSyncStatus('user_abc', 'binance');

      expect(mockPrisma.syncStatus.findUnique).toHaveBeenCalledWith({
        where: {
          userUid_exchange: {
            userUid: 'user_abc',
            exchange: 'binance',
          },
        },
      });
      expect(result).not.toBeNull();
      expect(result?.exchange).toBe('binance');
    });

    it('should return null when not found', async () => {
      (mockPrisma.syncStatus.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await repository.getSyncStatus('nonexistent', 'binance');

      expect(result).toBeNull();
    });
  });

  describe('getAllSyncStatuses', () => {
    it('should return all sync statuses ordered by updatedAt desc', async () => {
      const statuses = [mockSyncStatus, { ...mockSyncStatus, id: 'sync_456' }];
      (mockPrisma.syncStatus.findMany as jest.Mock).mockResolvedValue(statuses);

      const result = await repository.getAllSyncStatuses();

      expect(mockPrisma.syncStatus.findMany).toHaveBeenCalledWith({
        orderBy: { updatedAt: 'desc' },
      });
      expect(result).toHaveLength(2);
    });
  });

  describe('getSyncStatusesByUser', () => {
    it('should return sync statuses for a user', async () => {
      const statuses = [mockSyncStatus];
      (mockPrisma.syncStatus.findMany as jest.Mock).mockResolvedValue(statuses);

      const result = await repository.getSyncStatusesByUser('user_abc');

      expect(mockPrisma.syncStatus.findMany).toHaveBeenCalledWith({
        where: { userUid: 'user_abc' },
        orderBy: { updatedAt: 'desc' },
      });
      expect(result).toHaveLength(1);
    });
  });

  describe('getPendingSyncs', () => {
    it('should return pending and syncing statuses', async () => {
      const pendingStatus = { ...mockSyncStatus, status: SyncStatusEnum.pending };
      (mockPrisma.syncStatus.findMany as jest.Mock).mockResolvedValue([pendingStatus]);

      const result = await repository.getPendingSyncs();

      expect(mockPrisma.syncStatus.findMany).toHaveBeenCalledWith({
        where: {
          OR: [
            { status: SyncStatusEnum.pending },
            { status: SyncStatusEnum.syncing },
          ],
        },
        orderBy: { updatedAt: 'asc' },
      });
      expect(result[0]?.status).toBe('pending');
    });
  });

  describe('getErrorSyncs', () => {
    it('should return error statuses', async () => {
      const errorStatus = { ...mockSyncStatus, status: SyncStatusEnum.error, errorMessage: 'API failed' };
      (mockPrisma.syncStatus.findMany as jest.Mock).mockResolvedValue([errorStatus]);

      const result = await repository.getErrorSyncs();

      expect(mockPrisma.syncStatus.findMany).toHaveBeenCalledWith({
        where: { status: SyncStatusEnum.error },
        orderBy: { updatedAt: 'desc' },
      });
      expect(result[0]?.status).toBe('error');
    });
  });

  describe('deleteSyncStatus', () => {
    it('should delete sync status by user and exchange', async () => {
      (mockPrisma.syncStatus.delete as jest.Mock).mockResolvedValue(mockSyncStatus);

      await repository.deleteSyncStatus('user_abc', 'binance');

      expect(mockPrisma.syncStatus.delete).toHaveBeenCalledWith({
        where: {
          userUid_exchange: {
            userUid: 'user_abc',
            exchange: 'binance',
          },
        },
      });
    });
  });

  describe('resetSyncStatus', () => {
    it('should reset sync status to pending', async () => {
      const resetStatus = { ...mockSyncStatus, status: SyncStatusEnum.pending, lastSyncTime: null, errorMessage: null };
      (mockPrisma.syncStatus.update as jest.Mock).mockResolvedValue(resetStatus);

      const result = await repository.resetSyncStatus('user_abc', 'binance');

      expect(mockPrisma.syncStatus.update).toHaveBeenCalledWith({
        where: {
          userUid_exchange: {
            userUid: 'user_abc',
            exchange: 'binance',
          },
        },
        data: expect.objectContaining({
          status: SyncStatusEnum.pending,
          lastSyncTime: null,
          errorMessage: null,
        }),
      });
      expect(result.status).toBe('pending');
    });
  });
});
