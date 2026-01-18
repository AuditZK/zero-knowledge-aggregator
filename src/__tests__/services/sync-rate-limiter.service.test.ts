import { SyncRateLimiterService } from '../../services/sync-rate-limiter.service';

// Mock PrismaClient
const mockPrisma = {
  syncRateLimitLog: {
    findUnique: jest.fn(),
    upsert: jest.fn(),
    deleteMany: jest.fn(),
    findMany: jest.fn(),
    delete: jest.fn(),
  },
};

describe('SyncRateLimiterService', () => {
  let service: SyncRateLimiterService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new SyncRateLimiterService(mockPrisma as never);
  });

  describe('checkRateLimit', () => {
    const userUid = 'user_test123456789';
    const exchange = 'binance';

    it('should allow first sync for new user/exchange', async () => {
      mockPrisma.syncRateLimitLog.findUnique.mockResolvedValue(null);

      const result = await service.checkRateLimit(userUid, exchange);

      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('should allow sync after 23 hours have passed', async () => {
      const lastSync = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
      mockPrisma.syncRateLimitLog.findUnique.mockResolvedValue({
        userUid,
        exchange,
        lastSyncTime: lastSync,
        syncCount: 1,
      });

      const result = await service.checkRateLimit(userUid, exchange);

      expect(result.allowed).toBe(true);
    });

    it('should deny sync within 23-hour cooldown', async () => {
      const lastSync = new Date(Date.now() - 10 * 60 * 60 * 1000); // 10 hours ago
      mockPrisma.syncRateLimitLog.findUnique.mockResolvedValue({
        userUid,
        exchange,
        lastSyncTime: lastSync,
        syncCount: 5,
      });

      const result = await service.checkRateLimit(userUid, exchange);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Rate limit exceeded');
      expect(result.nextAllowedTime).toBeInstanceOf(Date);
    });

    it('should calculate correct next allowed time', async () => {
      const lastSync = new Date(Date.now() - 10 * 60 * 60 * 1000); // 10 hours ago
      mockPrisma.syncRateLimitLog.findUnique.mockResolvedValue({
        userUid,
        exchange,
        lastSyncTime: lastSync,
        syncCount: 1,
      });

      const result = await service.checkRateLimit(userUid, exchange);

      expect(result.nextAllowedTime).toBeDefined();
      // Next allowed time should be 23 hours after last sync
      const expectedNextTime = new Date(lastSync.getTime() + 23 * 60 * 60 * 1000);
      expect(result.nextAllowedTime?.getTime()).toBeCloseTo(expectedNextTime.getTime(), -3);
    });

    it('should allow sync on database error (fail-open)', async () => {
      mockPrisma.syncRateLimitLog.findUnique.mockRejectedValue(new Error('DB error'));

      const result = await service.checkRateLimit(userUid, exchange);

      expect(result.allowed).toBe(true);
    });
  });

  describe('recordSync', () => {
    const userUid = 'user_test123456789';
    const exchange = 'kraken';

    it('should upsert sync record', async () => {
      mockPrisma.syncRateLimitLog.upsert.mockResolvedValue({});

      await service.recordSync(userUid, exchange);

      expect(mockPrisma.syncRateLimitLog.upsert).toHaveBeenCalledWith({
        where: {
          userUid_exchange: { userUid, exchange },
        },
        update: {
          lastSyncTime: expect.any(Date),
          syncCount: { increment: 1 },
        },
        create: {
          userUid,
          exchange,
          lastSyncTime: expect.any(Date),
          syncCount: 1,
        },
      });
    });

    it('should handle database errors gracefully', async () => {
      mockPrisma.syncRateLimitLog.upsert.mockRejectedValue(new Error('DB error'));

      // Should not throw
      await expect(service.recordSync(userUid, exchange)).resolves.toBeUndefined();
    });
  });

  describe('cleanupOldLogs', () => {
    it('should delete logs older than retention period', async () => {
      mockPrisma.syncRateLimitLog.deleteMany.mockResolvedValue({ count: 5 });

      const result = await service.cleanupOldLogs();

      expect(result).toBe(5);
      expect(mockPrisma.syncRateLimitLog.deleteMany).toHaveBeenCalledWith({
        where: {
          lastSyncTime: {
            lt: expect.any(Date),
          },
        },
      });
    });

    it('should return 0 when no logs to clean', async () => {
      mockPrisma.syncRateLimitLog.deleteMany.mockResolvedValue({ count: 0 });

      const result = await service.cleanupOldLogs();

      expect(result).toBe(0);
    });

    it('should return 0 on database error', async () => {
      mockPrisma.syncRateLimitLog.deleteMany.mockRejectedValue(new Error('DB error'));

      const result = await service.cleanupOldLogs();

      expect(result).toBe(0);
    });
  });

  describe('getUserRateLimitStats', () => {
    const userUid = 'user_test123456789';

    it('should return user sync statistics', async () => {
      const mockLogs = [
        { exchange: 'binance', lastSyncTime: new Date(), syncCount: 10 },
        { exchange: 'kraken', lastSyncTime: new Date(), syncCount: 5 },
      ];
      mockPrisma.syncRateLimitLog.findMany.mockResolvedValue(mockLogs);

      const result = await service.getUserRateLimitStats(userUid);

      expect(result).toHaveLength(2);
      expect(result[0]).toHaveProperty('exchange', 'binance');
      expect(result[0]).toHaveProperty('syncCount', 10);
    });

    it('should return empty array when user has no logs', async () => {
      mockPrisma.syncRateLimitLog.findMany.mockResolvedValue([]);

      const result = await service.getUserRateLimitStats(userUid);

      expect(result).toEqual([]);
    });

    it('should return empty array on database error', async () => {
      mockPrisma.syncRateLimitLog.findMany.mockRejectedValue(new Error('DB error'));

      const result = await service.getUserRateLimitStats(userUid);

      expect(result).toEqual([]);
    });
  });

  describe('overrideRateLimit', () => {
    const userUid = 'user_test123456789';
    const exchange = 'ibkr';

    it('should delete rate limit record', async () => {
      mockPrisma.syncRateLimitLog.delete.mockResolvedValue({});

      await service.overrideRateLimit(userUid, exchange);

      expect(mockPrisma.syncRateLimitLog.delete).toHaveBeenCalledWith({
        where: {
          userUid_exchange: { userUid, exchange },
        },
      });
    });

    it('should handle database errors gracefully', async () => {
      mockPrisma.syncRateLimitLog.delete.mockRejectedValue(new Error('Not found'));

      // Should not throw
      await expect(service.overrideRateLimit(userUid, exchange)).resolves.toBeUndefined();
    });
  });
});
