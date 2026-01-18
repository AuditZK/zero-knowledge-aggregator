import { EquitySnapshotAggregator } from '../../services/equity-snapshot-aggregator';
import { SnapshotDataRepository } from '../../core/repositories/snapshot-data-repository';
import { ExchangeConnectionRepository } from '../../core/repositories/exchange-connection-repository';
import { UserRepository } from '../../core/repositories/user-repository';
import { UniversalConnectorCacheService } from '../../core/services/universal-connector-cache.service';

// Mock the logger
jest.mock('../../utils/secure-enclave-logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

describe('EquitySnapshotAggregator', () => {
  let service: EquitySnapshotAggregator;
  let mockSnapshotRepo: jest.Mocked<SnapshotDataRepository>;
  let mockConnectionRepo: jest.Mocked<ExchangeConnectionRepository>;
  let mockUserRepo: jest.Mocked<UserRepository>;
  let mockConnectorCache: jest.Mocked<UniversalConnectorCacheService>;

  const mockUser = {
    uid: 'user_test123',
    email: 'test@example.com',
    syncIntervalMinutes: 60,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockConnection = {
    id: 'conn_123',
    userUid: 'user_test123',
    exchange: 'binance',
    label: 'Main Account',
    encryptedApiKey: 'encrypted_api_key',
    encryptedApiSecret: 'encrypted_api_secret',
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockCredentials = {
    userUid: 'user_test123',
    exchange: 'binance',
    label: 'Main Account',
    apiKey: 'test_api_key',
    apiSecret: 'test_api_secret',
  };

  beforeEach(() => {
    mockSnapshotRepo = {
      upsertSnapshotData: jest.fn(),
      getSnapshotData: jest.fn(),
    } as unknown as jest.Mocked<SnapshotDataRepository>;

    mockConnectionRepo = {
      getConnectionsByUser: jest.fn(),
      getDecryptedCredentials: jest.fn(),
    } as unknown as jest.Mocked<ExchangeConnectionRepository>;

    mockUserRepo = {
      getUserByUid: jest.fn(),
    } as unknown as jest.Mocked<UserRepository>;

    mockConnectorCache = {
      getOrCreate: jest.fn(),
    } as unknown as jest.Mocked<UniversalConnectorCacheService>;

    service = new EquitySnapshotAggregator(
      mockSnapshotRepo,
      mockConnectionRepo,
      mockUserRepo,
      mockConnectorCache
    );
  });

  describe('buildSnapshot', () => {
    it('should return null when user is not found', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(null);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).toBeNull();
    });

    it('should return null when no active connection found', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([]);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).toBeNull();
    });

    it('should return null when credentials cannot be decrypted', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(null);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).toBeNull();
    });

    it('should build snapshot with basic balance connector', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        getBalance: jest.fn().mockResolvedValue({
          equity: 50000,
          unrealizedPnl: 500,
        }),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).not.toBeNull();
      expect(result!.totalEquity).toBe(50000);
      expect(result!.userUid).toBe('user_test123');
      expect(result!.exchange).toBe('binance');
    });

    it('should build snapshot with market types connector', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        detectMarketTypes: jest.fn().mockResolvedValue(['spot', 'swap']),
        getBalanceByMarket: jest.fn().mockImplementation((marketType: string) => {
          if (marketType === 'spot') return Promise.resolve({ equity: 30000, available_margin: 25000 });
          if (marketType === 'swap') return Promise.resolve({ equity: 20000, available_margin: 15000 });
          return Promise.resolve({ equity: 0 });
        }),
        getExecutedOrders: jest.fn().mockResolvedValue([]),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).not.toBeNull();
      expect(result!.totalEquity).toBe(50000);
      expect(result!.breakdown_by_market).toBeDefined();
    });

    it('should calculate unrealized PnL from positions', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        getBalance: jest.fn().mockResolvedValue({
          equity: 50000,
          unrealizedPnl: 0,
        }),
        getCurrentPositions: jest.fn().mockResolvedValue([
          { symbol: 'BTCUSDT', size: 1, unrealizedPnl: 1000 },
          { symbol: 'ETHUSDT', size: 2, unrealizedPnl: -500 },
        ]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).not.toBeNull();
      expect(result!.unrealizedPnL).toBe(500); // 1000 - 500
      expect(result!.realizedBalance).toBe(49500); // 50000 - 500
    });

    it('should handle connector errors gracefully', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        getBalance: jest.fn().mockRejectedValue(new Error('API rate limit exceeded')),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      await expect(service.buildSnapshot('user_test123', 'binance')).rejects.toThrow('API rate limit exceeded');
    });
  });

  describe('updateCurrentSnapshot', () => {
    it('should update snapshot in repository', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        getBalance: jest.fn().mockResolvedValue({
          equity: 50000,
          unrealizedPnl: 500,
        }),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      await service.updateCurrentSnapshot('user_test123', 'binance');

      expect(mockSnapshotRepo.upsertSnapshotData).toHaveBeenCalled();
    });

    it('should not update when snapshot build fails', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(null);

      await service.updateCurrentSnapshot('user_test123', 'binance');

      expect(mockSnapshotRepo.upsertSnapshotData).not.toHaveBeenCalled();
    });
  });

  describe('backfillIbkrHistoricalSnapshots', () => {
    it('should skip non-ibkr exchanges', async () => {
      await service.backfillIbkrHistoricalSnapshots('user_test123', 'binance');

      expect(mockConnectionRepo.getConnectionsByUser).not.toHaveBeenCalled();
    });

    it('should skip when no active connection found', async () => {
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([]);

      await service.backfillIbkrHistoricalSnapshots('user_test123', 'ibkr');

      expect(mockSnapshotRepo.upsertSnapshotData).not.toHaveBeenCalled();
    });

    it('should process IBKR historical data', async () => {
      const ibkrConnection = { ...mockConnection, exchange: 'ibkr' };
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([ibkrConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        getHistoricalSummaries: jest.fn().mockResolvedValue([
          {
            date: '20240115',
            breakdown: {
              global: { equity: 100000, unrealizedPnl: 1000 },
              stocks: { equity: 80000, unrealizedPnl: 800 },
            },
          },
          {
            date: '20240116',
            breakdown: {
              global: { equity: 101000, unrealizedPnl: 1100 },
              stocks: { equity: 81000, unrealizedPnl: 900 },
            },
          },
        ]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      await service.backfillIbkrHistoricalSnapshots('user_test123', 'ibkr');

      expect(mockSnapshotRepo.upsertSnapshotData).toHaveBeenCalledTimes(2);
    });

    it('should skip days with zero equity', async () => {
      const ibkrConnection = { ...mockConnection, exchange: 'ibkr' };
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([ibkrConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        getHistoricalSummaries: jest.fn().mockResolvedValue([
          {
            date: '20240115',
            breakdown: {
              global: { equity: 0, unrealizedPnl: 0 },
            },
          },
          {
            date: '20240116',
            breakdown: {
              global: { equity: 100000, unrealizedPnl: 1000 },
            },
          },
        ]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      await service.backfillIbkrHistoricalSnapshots('user_test123', 'ibkr');

      // Only the second day should be processed
      expect(mockSnapshotRepo.upsertSnapshotData).toHaveBeenCalledTimes(1);
    });
  });

  describe('balance breakdown conversion', () => {
    it('should build snapshot with balance breakdown connector', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        getBalanceBreakdown: jest.fn().mockResolvedValue({
          global: { equity: 100000, available_margin: 80000 },
          stocks: { equity: 60000, unrealizedPnl: 500, availableBalance: 50000 },
          futures_commodities: { equity: 40000, unrealizedPnl: 200, availableBalance: 35000 },
        }),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).not.toBeNull();
      expect(result!.totalEquity).toBe(100000);
      expect(result!.breakdown_by_market).toBeDefined();
      expect(result!.breakdown_by_market!.global).toBeDefined();
    });
  });

  describe('funding fees calculation', () => {
    it('should calculate funding fees for swap positions', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        detectMarketTypes: jest.fn().mockResolvedValue(['spot', 'swap']),
        getBalanceByMarket: jest.fn().mockImplementation((marketType: string) => {
          if (marketType === 'spot') return Promise.resolve({ equity: 30000 });
          if (marketType === 'swap') return Promise.resolve({ equity: 20000 });
          return Promise.resolve({ equity: 0 });
        }),
        getExecutedOrders: jest.fn().mockImplementation((marketType: string) => {
          if (marketType === 'swap') {
            return Promise.resolve([
              { id: '1', symbol: 'BTC-PERP', side: 'buy', price: 50000, amount: 1, cost: 50000, timestamp: Date.now() },
            ]);
          }
          return Promise.resolve([]);
        }),
        getFundingFees: jest.fn().mockResolvedValue([
          { amount: -15.5, symbol: 'BTC-PERP' },
        ]),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).not.toBeNull();
      expect(mockConnector.getFundingFees).toHaveBeenCalled();
    });

    it('should handle funding fees fetch failure gracefully', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        detectMarketTypes: jest.fn().mockResolvedValue(['swap']),
        getBalanceByMarket: jest.fn().mockResolvedValue({ equity: 20000 }),
        getExecutedOrders: jest.fn().mockResolvedValue([
          { id: '1', symbol: 'BTC-PERP', side: 'buy', price: 50000, amount: 1, cost: 50000, timestamp: Date.now() },
        ]),
        getFundingFees: jest.fn().mockRejectedValue(new Error('Funding API unavailable')),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).not.toBeNull();
      expect(result!.totalEquity).toBe(20000);
    });
  });

  describe('earn balance support', () => {
    it('should include earn balance when available', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        detectMarketTypes: jest.fn().mockResolvedValue(['spot']),
        getBalanceByMarket: jest.fn().mockResolvedValue({ equity: 30000 }),
        getEarnBalance: jest.fn().mockResolvedValue({ equity: 5000 }),
        getExecutedOrders: jest.fn().mockResolvedValue([]),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).not.toBeNull();
      expect(result!.totalEquity).toBe(35000); // 30000 + 5000 earn
      expect((result!.breakdown_by_market as Record<string, unknown>).earn).toBeDefined();
    });

    it('should handle earn balance fetch failure gracefully', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        detectMarketTypes: jest.fn().mockResolvedValue(['spot']),
        getBalanceByMarket: jest.fn().mockResolvedValue({ equity: 30000 }),
        getEarnBalance: jest.fn().mockRejectedValue(new Error('Earn not available')),
        getExecutedOrders: jest.fn().mockResolvedValue([]),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).not.toBeNull();
      expect(result!.totalEquity).toBe(30000);
    });
  });

  describe('snapshot data structure', () => {
    it('should generate correct snapshot ID format', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        getBalance: jest.fn().mockResolvedValue({ equity: 50000 }),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).not.toBeNull();
      expect(result!.id).toMatch(/^user_test123-binance-\d{4}-\d{2}-\d{2}T/);
    });

    it('should include all required snapshot fields', async () => {
      mockUserRepo.getUserByUid.mockResolvedValue(mockUser);
      mockConnectionRepo.getConnectionsByUser.mockResolvedValue([mockConnection]);
      mockConnectionRepo.getDecryptedCredentials.mockResolvedValue(mockCredentials);

      const mockConnector = {
        getBalance: jest.fn().mockResolvedValue({ equity: 50000 }),
        getCurrentPositions: jest.fn().mockResolvedValue([]),
      };
      mockConnectorCache.getOrCreate.mockReturnValue(mockConnector as never);

      const result = await service.buildSnapshot('user_test123', 'binance');

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('userUid');
      expect(result).toHaveProperty('timestamp');
      expect(result).toHaveProperty('exchange');
      expect(result).toHaveProperty('totalEquity');
      expect(result).toHaveProperty('realizedBalance');
      expect(result).toHaveProperty('unrealizedPnL');
      expect(result).toHaveProperty('deposits');
      expect(result).toHaveProperty('withdrawals');
      expect(result).toHaveProperty('breakdown_by_market');
      expect(result).toHaveProperty('createdAt');
      expect(result).toHaveProperty('updatedAt');
    });
  });
});
