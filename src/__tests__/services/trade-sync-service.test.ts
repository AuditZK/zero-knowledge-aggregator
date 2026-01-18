import { TradeSyncService } from '../../services/trade-sync-service';
import type { ExchangeConnectionRepository } from '../../core/repositories/exchange-connection-repository';
import type { SyncStatusRepository } from '../../core/repositories/sync-status-repository';
import type { UserRepository } from '../../core/repositories/user-repository';
import type { UniversalConnectorCacheService } from '../../core/services/universal-connector-cache.service';
import type { EncryptionService } from '../../services/encryption-service';
import { ExchangeConnectorFactory } from '../../external/factories/ExchangeConnectorFactory';

// Mock the factory
jest.mock('../../external/factories/ExchangeConnectorFactory');

describe('TradeSyncService', () => {
  let service: TradeSyncService;
  let mockExchangeConnectionRepo: jest.Mocked<ExchangeConnectionRepository>;
  let mockSyncStatusRepo: jest.Mocked<SyncStatusRepository>;
  let mockUserRepo: jest.Mocked<UserRepository>;
  let mockConnectorCache: jest.Mocked<UniversalConnectorCacheService>;
  let mockEncryptionService: jest.Mocked<EncryptionService>;
  let mockConnector: { getTrades: jest.Mock; testConnection: jest.Mock };

  beforeEach(() => {
    mockExchangeConnectionRepo = {
      getDecryptedCredentials: jest.fn(),
      getConnectionsByUser: jest.fn(),
      getUniqueCredentialsForUser: jest.fn(),
      findExistingConnection: jest.fn(),
      getConnectionsByCredentialsHash: jest.fn(),
      createConnection: jest.fn(),
    } as unknown as jest.Mocked<ExchangeConnectionRepository>;

    mockSyncStatusRepo = {
      upsertSyncStatus: jest.fn(),
      getAllSyncStatuses: jest.fn(),
    } as unknown as jest.Mocked<SyncStatusRepository>;

    mockUserRepo = {
      createUser: jest.fn(),
    } as unknown as jest.Mocked<UserRepository>;

    mockConnector = {
      getTrades: jest.fn(),
      testConnection: jest.fn(),
    };

    mockConnectorCache = {
      getOrCreate: jest.fn().mockReturnValue(mockConnector),
    } as unknown as jest.Mocked<UniversalConnectorCacheService>;

    mockEncryptionService = {
      createCredentialsHash: jest.fn(),
    } as unknown as jest.Mocked<EncryptionService>;

    // Mock the factory
    (ExchangeConnectorFactory.isSupported as jest.Mock).mockReturnValue(true);

    service = new TradeSyncService(
      mockExchangeConnectionRepo,
      mockSyncStatusRepo,
      mockUserRepo,
      mockConnectorCache,
      mockEncryptionService
    );
  });

  describe('syncUserTrades', () => {
    it('should sync trades successfully', async () => {
      mockUserRepo.createUser.mockResolvedValue(undefined as any);
      mockExchangeConnectionRepo.getUniqueCredentialsForUser.mockResolvedValue([
        { id: 'conn1', exchange: 'binance', label: 'main' }
      ] as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([
        { id: 'conn1', exchange: 'binance', label: 'main' }
      ] as any);
      mockExchangeConnectionRepo.getDecryptedCredentials.mockResolvedValue({
        exchange: 'binance',
        apiKey: 'key',
        apiSecret: 'secret'
      } as any);
      mockConnector.getTrades.mockResolvedValue([{ id: 1 }, { id: 2 }]);
      mockSyncStatusRepo.upsertSyncStatus.mockResolvedValue(undefined as any);

      const result = await service.syncUserTrades('user123');

      expect(result.success).toBe(true);
      expect(result.synced).toBe(2);
    });

    it('should handle sync failure', async () => {
      mockUserRepo.createUser.mockRejectedValue(new Error('DB error'));

      const result = await service.syncUserTrades('user123');

      expect(result.success).toBe(false);
      expect(result.message).toContain('Sync failed');
    });

    it('should handle user already exists (P2002)', async () => {
      const prismaError = new Error('User exists') as Error & { code: string };
      prismaError.code = 'P2002';
      mockUserRepo.createUser.mockRejectedValue(prismaError);
      mockExchangeConnectionRepo.getUniqueCredentialsForUser.mockResolvedValue([]);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([]);

      const result = await service.syncUserTrades('user123');

      // P2002 error is swallowed (user exists is ok), sync continues
      // With no connections, result shows 0 trades processed
      expect(result.synced).toBe(0);
    });
  });

  describe('syncExchangeTrades', () => {
    it('should sync trades from exchange', async () => {
      mockExchangeConnectionRepo.getDecryptedCredentials.mockResolvedValue({
        exchange: 'binance',
        apiKey: 'key',
        apiSecret: 'secret'
      } as any);
      mockConnector.getTrades.mockResolvedValue([{ id: 1 }, { id: 2 }, { id: 3 }]);
      mockSyncStatusRepo.upsertSyncStatus.mockResolvedValue(undefined as any);

      const result = await service.syncExchangeTrades('user123', 'conn1');

      expect(result).toBe(3);
      expect(mockSyncStatusRepo.upsertSyncStatus).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'completed',
          totalTrades: 3
        })
      );
    });

    it('should throw when credentials not found', async () => {
      mockExchangeConnectionRepo.getDecryptedCredentials.mockResolvedValue(null);

      await expect(service.syncExchangeTrades('user123', 'conn1'))
        .rejects.toThrow('Failed to get exchange credentials');
    });

    it('should update status to error on failure', async () => {
      mockExchangeConnectionRepo.getDecryptedCredentials.mockResolvedValue({
        exchange: 'binance',
        apiKey: 'key',
        apiSecret: 'secret'
      } as any);
      mockConnector.getTrades.mockRejectedValue(new Error('API error'));
      mockSyncStatusRepo.upsertSyncStatus.mockResolvedValue(undefined as any);

      await expect(service.syncExchangeTrades('user123', 'conn1'))
        .rejects.toThrow('API error');

      expect(mockSyncStatusRepo.upsertSyncStatus).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'error',
          errorMessage: 'API error'
        })
      );
    });

    it('should throw for unsupported exchange', async () => {
      mockExchangeConnectionRepo.getDecryptedCredentials.mockResolvedValue({
        exchange: 'unknown_exchange',
        apiKey: 'key',
        apiSecret: 'secret'
      } as any);
      (ExchangeConnectorFactory.isSupported as jest.Mock).mockReturnValue(false);
      mockSyncStatusRepo.upsertSyncStatus.mockResolvedValue(undefined as any);

      await expect(service.syncExchangeTrades('user123', 'conn1'))
        .rejects.toThrow('Exchange unknown_exchange not supported');
    });
  });

  describe('syncTradesForStatistics', () => {
    it('should return failure when no connections', async () => {
      mockExchangeConnectionRepo.getUniqueCredentialsForUser.mockResolvedValue([]);

      const result = await service.syncTradesForStatistics('user123');

      expect(result.success).toBe(false);
      expect(result.message).toBe('No active exchange connections found');
    });

    it('should sync multiple exchanges', async () => {
      mockExchangeConnectionRepo.getUniqueCredentialsForUser.mockResolvedValue([
        { id: 'conn1', exchange: 'binance', label: 'main' },
        { id: 'conn2', exchange: 'kraken', label: 'secondary' }
      ] as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([
        { id: 'conn1', exchange: 'binance', label: 'main' },
        { id: 'conn2', exchange: 'kraken', label: 'secondary' }
      ] as any);
      mockExchangeConnectionRepo.getDecryptedCredentials
        .mockResolvedValueOnce({ exchange: 'binance', apiKey: 'k1', apiSecret: 's1' } as any)
        .mockResolvedValueOnce({ exchange: 'kraken', apiKey: 'k2', apiSecret: 's2' } as any);
      mockConnector.getTrades
        .mockResolvedValueOnce([{ id: 1 }, { id: 2 }])
        .mockResolvedValueOnce([{ id: 3 }]);
      mockSyncStatusRepo.upsertSyncStatus.mockResolvedValue(undefined as any);

      const result = await service.syncTradesForStatistics('user123');

      expect(result.success).toBe(true);
      expect(result.synced).toBe(3);
    });

    it('should handle partial failures', async () => {
      mockExchangeConnectionRepo.getUniqueCredentialsForUser.mockResolvedValue([
        { id: 'conn1', exchange: 'binance', label: 'main' }
      ] as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([
        { id: 'conn1', exchange: 'binance', label: 'main' }
      ] as any);
      mockExchangeConnectionRepo.getDecryptedCredentials.mockResolvedValue(null);
      mockSyncStatusRepo.upsertSyncStatus.mockResolvedValue(undefined as any);

      const result = await service.syncTradesForStatistics('user123');

      // Should return 0 synced due to failure
      expect(result.synced).toBe(0);
    });

    it('should report skipped duplicates', async () => {
      mockExchangeConnectionRepo.getUniqueCredentialsForUser.mockResolvedValue([
        { id: 'conn1', exchange: 'binance', label: 'main' }
      ] as any);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([
        { id: 'conn1', exchange: 'binance', label: 'main' },
        { id: 'conn2', exchange: 'binance', label: 'duplicate' }
      ] as any);
      mockExchangeConnectionRepo.getDecryptedCredentials.mockResolvedValue({
        exchange: 'binance',
        apiKey: 'key',
        apiSecret: 'secret'
      } as any);
      mockConnector.getTrades.mockResolvedValue([{ id: 1 }]);
      mockSyncStatusRepo.upsertSyncStatus.mockResolvedValue(undefined as any);

      const result = await service.syncTradesForStatistics('user123');

      expect(result.message).toContain('1 duplicates skipped');
    });
  });

  describe('syncAllUsers', () => {
    it('should sync all users with sync statuses', async () => {
      mockSyncStatusRepo.getAllSyncStatuses.mockResolvedValue([
        { userUid: 'user1' },
        { userUid: 'user2' }
      ] as any);
      mockUserRepo.createUser.mockResolvedValue(undefined as any);
      mockExchangeConnectionRepo.getUniqueCredentialsForUser.mockResolvedValue([]);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([]);

      await service.syncAllUsers();

      // Should have called syncUserTrades for each user
      expect(mockExchangeConnectionRepo.getUniqueCredentialsForUser).toHaveBeenCalledTimes(2);
    });

    it('should continue on individual user failure', async () => {
      mockSyncStatusRepo.getAllSyncStatuses.mockResolvedValue([
        { userUid: 'user1' },
        { userUid: 'user2' }
      ] as any);
      mockUserRepo.createUser.mockRejectedValueOnce(new Error('User 1 error'));
      mockUserRepo.createUser.mockResolvedValueOnce(undefined as any);
      mockExchangeConnectionRepo.getUniqueCredentialsForUser.mockResolvedValue([]);
      mockExchangeConnectionRepo.getConnectionsByUser.mockResolvedValue([]);

      await expect(service.syncAllUsers()).resolves.not.toThrow();
    });

    it('should handle getAllSyncStatuses error', async () => {
      mockSyncStatusRepo.getAllSyncStatuses.mockRejectedValue(new Error('DB error'));

      await expect(service.syncAllUsers()).resolves.not.toThrow();
    });
  });

  describe('addExchangeConnection', () => {
    beforeEach(() => {
      mockUserRepo.createUser.mockResolvedValue(undefined as any);
      mockExchangeConnectionRepo.findExistingConnection.mockResolvedValue(null);
      mockExchangeConnectionRepo.getConnectionsByCredentialsHash.mockResolvedValue([]);
      mockEncryptionService.createCredentialsHash.mockReturnValue('hash123');
      mockConnector.testConnection.mockResolvedValue(true);
      mockExchangeConnectionRepo.createConnection.mockResolvedValue({ id: 'new-conn' } as any);
      mockSyncStatusRepo.upsertSyncStatus.mockResolvedValue(undefined as any);
    });

    it('should add new exchange connection', async () => {
      const result = await service.addExchangeConnection(
        'user123',
        'binance',
        'main',
        'api-key',
        'api-secret'
      );

      expect(result.success).toBe(true);
      expect(result.connectionId).toBe('new-conn');
    });

    it('should reject duplicate connection label', async () => {
      mockExchangeConnectionRepo.findExistingConnection.mockResolvedValue({ id: 'existing' } as any);

      const result = await service.addExchangeConnection(
        'user123',
        'binance',
        'main',
        'api-key',
        'api-secret'
      );

      expect(result.success).toBe(false);
      expect(result.message).toContain('already exists');
    });

    it('should reject invalid credentials', async () => {
      mockConnector.testConnection.mockResolvedValue(false);

      const result = await service.addExchangeConnection(
        'user123',
        'binance',
        'main',
        'bad-key',
        'bad-secret'
      );

      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid API credentials');
    });

    it('should suggest passphrase for exchanges that need it', async () => {
      mockConnector.testConnection.mockResolvedValue(false);

      const result = await service.addExchangeConnection(
        'user123',
        'bitget',
        'main',
        'api-key',
        'api-secret'
      );

      expect(result.success).toBe(false);
      expect(result.message).toContain('verify passphrase');
    });

    it('should accept passphrase for exchanges that support it', async () => {
      const result = await service.addExchangeConnection(
        'user123',
        'bitget',
        'main',
        'api-key',
        'api-secret',
        'passphrase'
      );

      expect(result.success).toBe(true);
    });

    it('should warn about duplicate credentials', async () => {
      mockExchangeConnectionRepo.getConnectionsByCredentialsHash.mockResolvedValue([
        { label: 'existing-connection' }
      ] as any);

      const result = await service.addExchangeConnection(
        'user123',
        'binance',
        'new-label',
        'same-key',
        'same-secret'
      );

      // Should still succeed but log warning
      expect(result.success).toBe(true);
    });

    it('should handle UNIQUE constraint error', async () => {
      mockExchangeConnectionRepo.createConnection.mockRejectedValue(
        new Error('UNIQUE constraint failed')
      );

      const result = await service.addExchangeConnection(
        'user123',
        'binance',
        'main',
        'api-key',
        'api-secret'
      );

      expect(result.success).toBe(false);
      expect(result.message).toContain('already exists');
    });

    it('should handle unsupported exchange for connection test', async () => {
      (ExchangeConnectorFactory.isSupported as jest.Mock).mockReturnValue(false);

      const result = await service.addExchangeConnection(
        'user123',
        'unknown_exchange',
        'main',
        'api-key',
        'api-secret'
      );

      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid API credentials');
    });
  });
});
