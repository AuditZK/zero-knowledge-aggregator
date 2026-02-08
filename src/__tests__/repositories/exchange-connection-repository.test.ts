import { ExchangeConnectionRepository } from '../../core/repositories/exchange-connection-repository';
import { EncryptionService } from '../../services/encryption-service';
import { PrismaClient } from '@prisma/client';

// Mock the logger
jest.mock('../../utils/secure-enclave-logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

// Mock MemoryProtectionService
jest.mock('../../services/memory-protection.service', () => ({
  MemoryProtectionService: {
    wipeObject: jest.fn(),
  },
}));

describe('ExchangeConnectionRepository', () => {
  let repository: ExchangeConnectionRepository;
  let mockPrisma: jest.Mocked<PrismaClient>;
  let mockEncryptionService: jest.Mocked<EncryptionService>;

  const mockConnection = {
    id: 'conn_123',
    userUid: 'user_test123',
    exchange: 'binance',
    label: 'Main Account',
    encryptedApiKey: 'encrypted_key',
    encryptedApiSecret: 'encrypted_secret',
    encryptedPassphrase: null,
    credentialsHash: 'hash_abc123',
    syncIntervalMinutes: 60,
    isActive: true,
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01'),
  };

  beforeEach(() => {
    mockPrisma = {
      exchangeConnection: {
        create: jest.fn(),
        findUnique: jest.fn(),
        findFirst: jest.fn(),
        findMany: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
        count: jest.fn(),
      },
    } as unknown as jest.Mocked<PrismaClient>;

    mockEncryptionService = {
      encrypt: jest.fn(),
      decrypt: jest.fn(),
      createCredentialsHash: jest.fn(),
    } as unknown as jest.Mocked<EncryptionService>;

    repository = new ExchangeConnectionRepository(
      mockPrisma,
      mockEncryptionService
    );
  });

  describe('createConnection', () => {
    it('should create a new connection with encrypted credentials', async () => {
      mockEncryptionService.encrypt
        .mockResolvedValueOnce('encrypted_api_key')
        .mockResolvedValueOnce('encrypted_api_secret');
      mockEncryptionService.createCredentialsHash.mockReturnValue('hash_123');
      (mockPrisma.exchangeConnection.create as jest.Mock).mockResolvedValue(mockConnection);

      const credentials = {
        userUid: 'user_test123',
        exchange: 'binance',
        label: 'Main Account',
        apiKey: 'my_api_key',
        apiSecret: 'my_api_secret',
      };

      const result = await repository.createConnection(credentials);

      expect(mockEncryptionService.encrypt).toHaveBeenCalledWith('my_api_key');
      expect(mockEncryptionService.encrypt).toHaveBeenCalledWith('my_api_secret');
      expect(mockEncryptionService.createCredentialsHash).toHaveBeenCalled();
      expect(result.id).toBe('conn_123');
      expect(result.exchange).toBe('binance');
    });

    it('should encrypt passphrase when provided', async () => {
      mockEncryptionService.encrypt
        .mockResolvedValueOnce('encrypted_api_key')
        .mockResolvedValueOnce('encrypted_api_secret')
        .mockResolvedValueOnce('encrypted_passphrase');
      mockEncryptionService.createCredentialsHash.mockReturnValue('hash_123');
      (mockPrisma.exchangeConnection.create as jest.Mock).mockResolvedValue({
        ...mockConnection,
        encryptedPassphrase: 'encrypted_passphrase',
      });

      const credentials = {
        userUid: 'user_test123',
        exchange: 'kucoin',
        label: 'KuCoin Account',
        apiKey: 'my_api_key',
        apiSecret: 'my_api_secret',
        passphrase: 'my_passphrase',
      };

      await repository.createConnection(credentials);

      expect(mockEncryptionService.encrypt).toHaveBeenCalledWith('my_passphrase');
    });

    it('should throw error for duplicate exchange connection', async () => {
      mockEncryptionService.encrypt.mockResolvedValue('encrypted');
      mockEncryptionService.createCredentialsHash.mockReturnValue('hash');
      const prismaError = new Error('Unique constraint violation') as Error & { code: string };
      prismaError.code = 'P2002';
      (mockPrisma.exchangeConnection.create as jest.Mock).mockRejectedValue(prismaError);

      const credentials = {
        userUid: 'user_test123',
        exchange: 'binance',
        label: 'Duplicate',
        apiKey: 'key',
        apiSecret: 'secret',
      };

      await expect(repository.createConnection(credentials)).rejects.toThrow(
        'Exchange binance with label "Duplicate" is already connected'
      );
    });
  });

  describe('getConnectionById', () => {
    it('should return connection when found', async () => {
      (mockPrisma.exchangeConnection.findUnique as jest.Mock).mockResolvedValue(mockConnection);

      const result = await repository.getConnectionById('conn_123');

      expect(result).not.toBeNull();
      expect(result!.id).toBe('conn_123');
    });

    it('should return null when connection not found', async () => {
      (mockPrisma.exchangeConnection.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await repository.getConnectionById('nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('getConnectionsByUser', () => {
    it('should return all connections for user', async () => {
      const connections = [
        mockConnection,
        { ...mockConnection, id: 'conn_456', exchange: 'kraken' },
      ];
      (mockPrisma.exchangeConnection.findMany as jest.Mock).mockResolvedValue(connections);

      const result = await repository.getConnectionsByUser('user_test123');

      expect(result.length).toBe(2);
    });

    it('should filter active connections when activeOnly is true', async () => {
      (mockPrisma.exchangeConnection.findMany as jest.Mock).mockResolvedValue([mockConnection]);

      await repository.getConnectionsByUser('user_test123', true);

      expect(mockPrisma.exchangeConnection.findMany).toHaveBeenCalledWith({
        where: { userUid: 'user_test123', isActive: true },
        orderBy: { createdAt: 'desc' },
      });
    });
  });

  describe('getDecryptedCredentials', () => {
    it('should decrypt and return credentials for active connection', async () => {
      (mockPrisma.exchangeConnection.findUnique as jest.Mock).mockResolvedValue(mockConnection);
      mockEncryptionService.decrypt
        .mockResolvedValueOnce('decrypted_api_key')
        .mockResolvedValueOnce('decrypted_api_secret');

      const result = await repository.getDecryptedCredentials('conn_123');

      expect(result).not.toBeNull();
      expect(result!.apiKey).toBe('decrypted_api_key');
      expect(result!.apiSecret).toBe('decrypted_api_secret');
    });

    it('should return null when connection not found', async () => {
      (mockPrisma.exchangeConnection.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await repository.getDecryptedCredentials('nonexistent');

      expect(result).toBeNull();
    });

    it('should return null when decryption fails', async () => {
      (mockPrisma.exchangeConnection.findUnique as jest.Mock).mockResolvedValue(mockConnection);
      mockEncryptionService.decrypt.mockRejectedValue(new Error('Decryption failed'));

      const result = await repository.getDecryptedCredentials('conn_123');

      expect(result).toBeNull();
    });

    it('should decrypt passphrase when present', async () => {
      const connectionWithPassphrase = {
        ...mockConnection,
        encryptedPassphrase: 'encrypted_passphrase',
      };
      (mockPrisma.exchangeConnection.findUnique as jest.Mock).mockResolvedValue(connectionWithPassphrase);
      mockEncryptionService.decrypt
        .mockResolvedValueOnce('decrypted_api_key')
        .mockResolvedValueOnce('decrypted_api_secret')
        .mockResolvedValueOnce('decrypted_passphrase');

      const result = await repository.getDecryptedCredentials('conn_123');

      expect(result!.passphrase).toBe('decrypted_passphrase');
    });
  });

  describe('useDecryptedCredentials', () => {
    it('should execute operation with credentials and wipe after', async () => {
      (mockPrisma.exchangeConnection.findUnique as jest.Mock).mockResolvedValue(mockConnection);
      mockEncryptionService.decrypt
        .mockResolvedValueOnce('api_key')
        .mockResolvedValueOnce('api_secret');

      const { MemoryProtectionService } = jest.requireMock('../../services/memory-protection.service');
      const operation = jest.fn().mockResolvedValue('result');

      const result = await repository.useDecryptedCredentials('conn_123', operation);

      expect(result).toBe('result');
      expect(operation).toHaveBeenCalledWith(expect.objectContaining({
        apiKey: 'api_key',
        apiSecret: 'api_secret',
      }));
      expect(MemoryProtectionService.wipeObject).toHaveBeenCalled();
    });

    it('should return null when credentials not found', async () => {
      (mockPrisma.exchangeConnection.findUnique as jest.Mock).mockResolvedValue(null);

      const operation = jest.fn();
      const result = await repository.useDecryptedCredentials('nonexistent', operation);

      expect(result).toBeNull();
      expect(operation).not.toHaveBeenCalled();
    });

    it('should wipe credentials even when operation throws', async () => {
      (mockPrisma.exchangeConnection.findUnique as jest.Mock).mockResolvedValue(mockConnection);
      mockEncryptionService.decrypt.mockResolvedValue('decrypted');

      const { MemoryProtectionService } = jest.requireMock('../../services/memory-protection.service');
      const operation = jest.fn().mockRejectedValue(new Error('Operation failed'));

      await expect(repository.useDecryptedCredentials('conn_123', operation)).rejects.toThrow('Operation failed');
      expect(MemoryProtectionService.wipeObject).toHaveBeenCalled();
    });
  });

  describe('updateConnection', () => {
    it('should update label without re-encrypting credentials', async () => {
      (mockPrisma.exchangeConnection.update as jest.Mock).mockResolvedValue({
        ...mockConnection,
        label: 'New Label',
      });

      const result = await repository.updateConnection('conn_123', { label: 'New Label' });

      expect(result.label).toBe('New Label');
      expect(mockEncryptionService.encrypt).not.toHaveBeenCalled();
    });

    it('should update isActive status', async () => {
      (mockPrisma.exchangeConnection.update as jest.Mock).mockResolvedValue({
        ...mockConnection,
        isActive: false,
      });

      const result = await repository.updateConnection('conn_123', { isActive: false });

      expect(result.isActive).toBe(false);
    });

    it('should re-encrypt and update credentials hash when credentials change', async () => {
      (mockPrisma.exchangeConnection.findUnique as jest.Mock).mockResolvedValue(mockConnection);
      mockEncryptionService.encrypt.mockResolvedValue('new_encrypted_key');
      mockEncryptionService.decrypt.mockResolvedValue('old_secret');
      mockEncryptionService.createCredentialsHash.mockReturnValue('new_hash');
      (mockPrisma.exchangeConnection.update as jest.Mock).mockResolvedValue({
        ...mockConnection,
        encryptedApiKey: 'new_encrypted_key',
        credentialsHash: 'new_hash',
      });

      await repository.updateConnection('conn_123', { apiKey: 'new_key' });

      expect(mockEncryptionService.encrypt).toHaveBeenCalledWith('new_key');
      expect(mockEncryptionService.createCredentialsHash).toHaveBeenCalled();
    });
  });

  describe('deleteConnection', () => {
    it('should delete connection by id', async () => {
      (mockPrisma.exchangeConnection.delete as jest.Mock).mockResolvedValue(mockConnection);

      await repository.deleteConnection('conn_123');

      expect(mockPrisma.exchangeConnection.delete).toHaveBeenCalledWith({
        where: { id: 'conn_123' },
      });
    });
  });

  describe('getActiveUserUids', () => {
    it('should return unique user UIDs with active connections', async () => {
      (mockPrisma.exchangeConnection.findMany as jest.Mock).mockResolvedValue([
        { userUid: 'user_1' },
        { userUid: 'user_2' },
        { userUid: 'user_3' },
      ]);

      const result = await repository.getActiveUserUids();

      expect(result).toEqual(['user_1', 'user_2', 'user_3']);
    });
  });

  describe('getActiveConnectionsWithIntervals', () => {
    it('should return connections with sync intervals', async () => {
      (mockPrisma.exchangeConnection.findMany as jest.Mock).mockResolvedValue([
        { userUid: 'user_1', exchange: 'binance', syncIntervalMinutes: 60 },
        { userUid: 'user_1', exchange: 'kraken', syncIntervalMinutes: 120 },
      ]);

      const result = await repository.getActiveConnectionsWithIntervals();

      expect(result.length).toBe(2);
      expect(result[0]).toEqual({
        userUid: 'user_1',
        exchange: 'binance',
        syncIntervalMinutes: 60,
      });
    });
  });

  describe('findExistingConnection', () => {
    it('should find connection by user, exchange, and label', async () => {
      (mockPrisma.exchangeConnection.findFirst as jest.Mock).mockResolvedValue(mockConnection);

      const result = await repository.findExistingConnection('user_test123', 'binance', 'Main Account');

      expect(result).not.toBeNull();
      expect(result!.id).toBe('conn_123');
    });

    it('should return null when no matching connection', async () => {
      (mockPrisma.exchangeConnection.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await repository.findExistingConnection('user_test123', 'binance', 'Nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('getUniqueCredentialsForUser', () => {
    it('should filter connections by unique credentials hash', async () => {
      const connections = [
        { ...mockConnection, credentialsHash: 'hash_1' },
        { ...mockConnection, id: 'conn_456', credentialsHash: 'hash_1' }, // duplicate
        { ...mockConnection, id: 'conn_789', credentialsHash: 'hash_2' },
      ];
      (mockPrisma.exchangeConnection.findMany as jest.Mock).mockResolvedValue(connections);

      const result = await repository.getUniqueCredentialsForUser('user_test123');

      expect(result.length).toBe(2);
    });
  });

  describe('countConnectionsByUser', () => {
    it('should return count of active connections for user', async () => {
      (mockPrisma.exchangeConnection.count as jest.Mock).mockResolvedValue(3);

      const result = await repository.countConnectionsByUser('user_test123');

      expect(result).toBe(3);
    });
  });

  describe('countAllActiveConnections', () => {
    it('should return total count of all active connections', async () => {
      (mockPrisma.exchangeConnection.count as jest.Mock).mockResolvedValue(100);

      const result = await repository.countAllActiveConnections();

      expect(result).toBe(100);
    });
  });
});
