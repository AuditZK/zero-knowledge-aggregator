import { UserRepository } from '../../core/repositories/user-repository';
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

describe('UserRepository', () => {
  let repository: UserRepository;
  let mockPrisma: jest.Mocked<PrismaClient>;

  const mockPrismaUser = {
    id: 'user_id_123',
    uid: 'user_uid_abc',
    syncIntervalMinutes: 60,
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-15'),
  };

  beforeEach(() => {
    mockPrisma = {
      user: {
        upsert: jest.fn(),
        findUnique: jest.fn(),
        findMany: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
        count: jest.fn(),
      },
    } as unknown as jest.Mocked<PrismaClient>;

    repository = new UserRepository(mockPrisma);
  });

  describe('createUser', () => {
    it('should create a new user via upsert', async () => {
      (mockPrisma.user.upsert as jest.Mock).mockResolvedValue(mockPrismaUser);

      const result = await repository.createUser({ uid: 'user_uid_abc' });

      expect(mockPrisma.user.upsert).toHaveBeenCalledWith({
        where: { uid: 'user_uid_abc' },
        update: {},
        create: { uid: 'user_uid_abc' },
      });
      expect(result.id).toBe('user_id_123');
      expect(result.uid).toBe('user_uid_abc');
      expect(result.syncIntervalMinutes).toBe(60);
    });
  });

  describe('getUserByUid', () => {
    it('should return user when found', async () => {
      (mockPrisma.user.findUnique as jest.Mock).mockResolvedValue(mockPrismaUser);

      const result = await repository.getUserByUid('user_uid_abc');

      expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
        where: { uid: 'user_uid_abc' },
      });
      expect(result).not.toBeNull();
      expect(result?.uid).toBe('user_uid_abc');
    });

    it('should return null when user not found', async () => {
      (mockPrisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await repository.getUserByUid('nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('getUserById', () => {
    it('should return user when found', async () => {
      (mockPrisma.user.findUnique as jest.Mock).mockResolvedValue(mockPrismaUser);

      const result = await repository.getUserById('user_id_123');

      expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'user_id_123' },
      });
      expect(result).not.toBeNull();
      expect(result?.id).toBe('user_id_123');
    });

    it('should return null when user not found', async () => {
      (mockPrisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await repository.getUserById('nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('updateUser', () => {
    it('should update user and return updated user', async () => {
      const updatedUser = { ...mockPrismaUser, syncIntervalMinutes: 120 };
      (mockPrisma.user.update as jest.Mock).mockResolvedValue(updatedUser);

      const result = await repository.updateUser('user_uid_abc', { syncIntervalMinutes: 120 });

      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { uid: 'user_uid_abc' },
        data: { syncIntervalMinutes: 120 },
      });
      expect(result.syncIntervalMinutes).toBe(120);
    });
  });

  describe('deleteUser', () => {
    it('should delete user by uid', async () => {
      (mockPrisma.user.delete as jest.Mock).mockResolvedValue(mockPrismaUser);

      await repository.deleteUser('user_uid_abc');

      expect(mockPrisma.user.delete).toHaveBeenCalledWith({
        where: { uid: 'user_uid_abc' },
      });
    });
  });

  describe('userExists', () => {
    it('should return true when user exists', async () => {
      (mockPrisma.user.count as jest.Mock).mockResolvedValue(1);

      const result = await repository.userExists('user_uid_abc');

      expect(result).toBe(true);
    });

    it('should return false when user does not exist', async () => {
      (mockPrisma.user.count as jest.Mock).mockResolvedValue(0);

      const result = await repository.userExists('nonexistent');

      expect(result).toBe(false);
    });
  });

  describe('getAllUsers', () => {
    it('should return all users ordered by createdAt desc', async () => {
      const users = [mockPrismaUser, { ...mockPrismaUser, id: 'user_2', uid: 'uid_2' }];
      (mockPrisma.user.findMany as jest.Mock).mockResolvedValue(users);

      const result = await repository.getAllUsers();

      expect(mockPrisma.user.findMany).toHaveBeenCalledWith({
        orderBy: { createdAt: 'desc' },
      });
      expect(result).toHaveLength(2);
    });
  });

  describe('countUsers', () => {
    it('should return total user count', async () => {
      (mockPrisma.user.count as jest.Mock).mockResolvedValue(42);

      const result = await repository.countUsers();

      expect(result).toBe(42);
    });
  });

  describe('getUserStats', () => {
    it('should return user statistics', async () => {
      const mockUserWithStats = {
        ...mockPrismaUser,
        _count: {
          snapshots: 10,
          exchangeConnections: 3,
        },
        syncStatuses: [
          { totalTrades: 50 },
          { totalTrades: 25 },
        ],
      };
      (mockPrisma.user.findUnique as jest.Mock).mockResolvedValue(mockUserWithStats);

      const result = await repository.getUserStats('user_uid_abc');

      expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
        where: { uid: 'user_uid_abc' },
        include: {
          _count: {
            select: {
              snapshots: true,
              exchangeConnections: true,
            },
          },
          syncStatuses: true,
        },
      });
      expect(result.totalTrades).toBe(75);
      expect(result.totalPositions).toBe(10);
      expect(result.exchangeConnections).toBe(3);
      expect(result.accountAge).toBeGreaterThanOrEqual(0);
    });

    it('should throw error when user not found', async () => {
      (mockPrisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(repository.getUserStats('nonexistent'))
        .rejects.toThrow('User with UID nonexistent not found');
    });
  });
});
