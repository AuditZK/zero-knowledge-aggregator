import { DailySyncSchedulerService } from '../../services/daily-sync-scheduler.service';
import type { UserRepository } from '../../core/repositories/user-repository';
import type { ExchangeConnectionRepository } from '../../core/repositories/exchange-connection-repository';
import type { SnapshotDataRepository } from '../../core/repositories/snapshot-data-repository';
import type { EquitySnapshotAggregator } from '../../services/equity-snapshot-aggregator';
import type { SnapshotData } from '../../types';

describe('DailySyncSchedulerService', () => {
  let service: DailySyncSchedulerService;
  let mockUserRepo: jest.Mocked<UserRepository>;
  let mockExchangeConnectionRepo: jest.Mocked<ExchangeConnectionRepository>;
  let mockSnapshotDataRepo: jest.Mocked<SnapshotDataRepository>;
  let mockSnapshotAggregator: jest.Mocked<EquitySnapshotAggregator>;

  const createMockSnapshot = (userUid: string, exchange: string): SnapshotData => ({
    id: `snapshot-${userUid}-${exchange}`,
    userUid,
    exchange,
    timestamp: new Date().toISOString(),
    totalEquity: 10000,
    realizedBalance: 8000,
    unrealizedPnL: 2000,
    deposits: 0,
    withdrawals: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  beforeEach(() => {
    mockUserRepo = {
      getAllUsers: jest.fn(),
      getUserByUid: jest.fn(),
      createUser: jest.fn(),
      updateUser: jest.fn(),
      deleteUser: jest.fn(),
    } as unknown as jest.Mocked<UserRepository>;

    mockExchangeConnectionRepo = {
      getConnectionsByUser: jest.fn(),
      getConnection: jest.fn(),
      createConnection: jest.fn(),
      updateConnection: jest.fn(),
      deleteConnection: jest.fn(),
    } as unknown as jest.Mocked<ExchangeConnectionRepository>;

    mockSnapshotDataRepo = {
      upsertSnapshotsTransactional: jest.fn(),
      getSnapshotData: jest.fn(),
      createSnapshot: jest.fn(),
      getLatestSnapshot: jest.fn(),
    } as unknown as jest.Mocked<SnapshotDataRepository>;

    mockSnapshotAggregator = {
      buildSnapshot: jest.fn(),
    } as unknown as jest.Mocked<EquitySnapshotAggregator>;

    service = new DailySyncSchedulerService(
      mockUserRepo,
      mockExchangeConnectionRepo,
      mockSnapshotAggregator,
      mockSnapshotDataRepo
    );
  });

  afterEach(() => {
    service.stop();
  });

  describe('start', () => {
    it('should start the cron scheduler', () => {
      service.start();

      const status = service.getStatus();
      expect(status.isRunning).toBe(true);
    });

    it('should not start twice if already running', () => {
      service.start();
      service.start(); // Second call should be ignored

      const status = service.getStatus();
      expect(status.isRunning).toBe(true);
    });
  });

  describe('stop', () => {
    it('should stop the cron scheduler', () => {
      service.start();
      service.stop();

      const status = service.getStatus();
      expect(status.isRunning).toBe(false);
    });

    it('should be safe to call stop when not running', () => {
      expect(() => {
        service.stop();
      }).not.toThrow();
    });
  });

  describe('getStatus', () => {
    it('should return status when not running', () => {
      const status = service.getStatus();

      expect(status.isRunning).toBe(false);
      expect(status.syncInProgress).toBe(false);
      expect(status.nextSyncTime).toBeInstanceOf(Date);
    });

    it('should return status when running', () => {
      service.start();

      const status = service.getStatus();

      expect(status.isRunning).toBe(true);
      expect(status.syncInProgress).toBe(false);
    });
  });

  describe('getNextSyncTime', () => {
    it('should return tomorrow at 00:00 UTC', () => {
      const nextSync = service.getNextSyncTime();
      const now = new Date();

      expect(nextSync.getUTCHours()).toBe(0);
      expect(nextSync.getUTCMinutes()).toBe(0);
      expect(nextSync.getUTCSeconds()).toBe(0);
      expect(nextSync.getTime()).toBeGreaterThan(now.getTime());
    });
  });

  describe('triggerManualSync', () => {
    it('should complete sync with no users', async () => {
      mockUserRepo.getAllUsers.mockResolvedValue([]);

      await service.triggerManualSync();

      expect(mockUserRepo.getAllUsers).toHaveBeenCalled();
    });

    it('should sync users with connections', async () => {
      const users = [{ uid: 'user1' }, { uid: 'user2' }];
      mockUserRepo.getAllUsers.mockResolvedValue(users as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([
        { exchange: 'binance' } as any
      ]);
      mockSnapshotAggregator.buildSnapshot.mockResolvedValue(
        createMockSnapshot('user1', 'binance')
      );
      (mockSnapshotDataRepo.upsertSnapshotsTransactional as jest.Mock).mockResolvedValue(undefined);

      await service.triggerManualSync();

      expect(mockUserRepo.getAllUsers).toHaveBeenCalled();
      expect(mockExchangeConnectionRepo.getConnectionsByUser).toHaveBeenCalledTimes(2);
    });

    it('should skip users with no connections', async () => {
      const users = [{ uid: 'user1' }];
      mockUserRepo.getAllUsers.mockResolvedValue(users as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([]);

      await service.triggerManualSync();

      expect(mockSnapshotAggregator.buildSnapshot).not.toHaveBeenCalled();
    });

    it('should handle multiple exchanges per user', async () => {
      const users = [{ uid: 'user1' }];
      mockUserRepo.getAllUsers.mockResolvedValue(users as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([
        { exchange: 'binance' } as any,
        { exchange: 'kraken' } as any,
      ]);
      mockSnapshotAggregator.buildSnapshot
        .mockResolvedValueOnce(createMockSnapshot('user1', 'binance'))
        .mockResolvedValueOnce(createMockSnapshot('user1', 'kraken'));
      (mockSnapshotDataRepo.upsertSnapshotsTransactional as jest.Mock).mockResolvedValue(undefined);

      await service.triggerManualSync();

      expect(mockSnapshotAggregator.buildSnapshot).toHaveBeenCalledTimes(2);
      expect(mockSnapshotDataRepo.upsertSnapshotsTransactional).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({ exchange: 'binance' }),
          expect.objectContaining({ exchange: 'kraken' }),
        ])
      );
    });

    it('should abort atomic sync when one exchange fails', async () => {
      const users = [{ uid: 'user1' }];
      mockUserRepo.getAllUsers.mockResolvedValue(users as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([
        { exchange: 'binance' } as any,
        { exchange: 'kraken' } as any,
      ]);
      mockSnapshotAggregator.buildSnapshot
        .mockResolvedValueOnce(createMockSnapshot('user1', 'binance'))
        .mockResolvedValueOnce(null); // kraken fails

      await service.triggerManualSync();

      // Should not save any snapshots (atomic failure)
      expect(mockSnapshotDataRepo.upsertSnapshotsTransactional).not.toHaveBeenCalled();
    });

    it('should handle user processing error', async () => {
      const users = [{ uid: 'user1' }];
      mockUserRepo.getAllUsers.mockResolvedValue(users as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockRejectedValue(
        new Error('Database error')
      );

      // Should not throw
      await expect(service.triggerManualSync()).resolves.not.toThrow();
    });

    it('should handle snapshot save error', async () => {
      const users = [{ uid: 'user1' }];
      mockUserRepo.getAllUsers.mockResolvedValue(users as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([
        { exchange: 'binance' } as any,
      ]);
      mockSnapshotAggregator.buildSnapshot.mockResolvedValue(
        createMockSnapshot('user1', 'binance')
      );
      mockSnapshotDataRepo.upsertSnapshotsTransactional.mockRejectedValue(
        new Error('Transaction failed')
      );

      // Should not throw
      await expect(service.triggerManualSync()).resolves.not.toThrow();
    });

    it('should prevent concurrent syncs', async () => {
      const users = [{ uid: 'user1' }];
      mockUserRepo.getAllUsers.mockImplementation(async () => {
        // Simulate slow operation
        await new Promise(resolve => setTimeout(resolve, 100));
        return users as any;
      });
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([]);

      // Start two syncs simultaneously
      const sync1 = service.triggerManualSync();
      const sync2 = service.triggerManualSync();

      await Promise.all([sync1, sync2]);

      // Only one should have actually run (the other was skipped)
      expect(mockUserRepo.getAllUsers).toHaveBeenCalledTimes(1);
    });

    it('should handle buildSnapshot throwing error', async () => {
      const users = [{ uid: 'user1' }];
      mockUserRepo.getAllUsers.mockResolvedValue(users as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([
        { exchange: 'binance' } as any,
      ]);
      mockSnapshotAggregator.buildSnapshot.mockRejectedValue(
        new Error('Exchange API error')
      );

      await expect(service.triggerManualSync()).resolves.not.toThrow();
    });
  });
});
