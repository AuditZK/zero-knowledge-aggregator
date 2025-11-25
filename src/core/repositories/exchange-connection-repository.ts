import { injectable, inject } from 'tsyringe';
import { PrismaClient, ExchangeConnection as PrismaExchangeConnection } from '@prisma/client';
import { ExchangeConnection, ExchangeCredentials } from '../../types';
import { EncryptionService } from '../../services/encryption-service';
import { getLogger } from '../../utils/secure-enclave-logger';

const logger = getLogger('ExchangeConnectionRepository');

@injectable()
export class ExchangeConnectionRepository {
  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient,
  ) {}

  async createConnection(credentials: ExchangeCredentials): Promise<ExchangeConnection> {
    const encryptedApiKey = EncryptionService.encrypt(credentials.apiKey);
    const encryptedApiSecret = EncryptionService.encrypt(credentials.apiSecret);
    const encryptedPassphrase = credentials.passphrase
      ? EncryptionService.encrypt(credentials.passphrase)
      : null;

    // Create hash of credentials to detect duplicate accounts
    const credentialsHash = EncryptionService.createCredentialsHash(
      credentials.apiKey,
      credentials.apiSecret,
      credentials.passphrase,
    );

    try {
      const connection = await this.prisma.exchangeConnection.create({
        data: {
          userUid: credentials.userUid,
          exchange: credentials.exchange,
          label: credentials.label,
          encryptedApiKey,
          encryptedApiSecret,
          encryptedPassphrase,
          credentialsHash,
          isActive: credentials.isActive ?? true,
        },
      });

      return this.mapPrismaConnectionToConnection(connection);
    } catch (error: any) {
      // Handle unique constraint violation (P2002)
      if (error.code === 'P2002') {
        throw new Error(`Exchange ${credentials.exchange} is already connected`);
      }
      throw error;
    }
  }

  async getConnectionById(id: string): Promise<ExchangeConnection | null> {
    const connection = await this.prisma.exchangeConnection.findUnique({
      where: { id },
    });

    return connection ? this.mapPrismaConnectionToConnection(connection) : null;
  }

  async getConnectionsByUser(userUid: string, activeOnly: boolean = false): Promise<ExchangeConnection[]> {
    const where: any = { userUid };
    if (activeOnly) {
      where.isActive = true;
    }

    const connections = await this.prisma.exchangeConnection.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });

    return connections.map(this.mapPrismaConnectionToConnection);
  }

  async getDecryptedCredentials(connectionId: string): Promise<ExchangeCredentials | null> {
    const connection = await this.prisma.exchangeConnection.findUnique({
      where: { id: connectionId, isActive: true },
    });

    if (!connection) {
      return null;
    }

    try {
      const apiKey = EncryptionService.decrypt(connection.encryptedApiKey);
      const apiSecret = EncryptionService.decrypt(connection.encryptedApiSecret);
      const passphrase = connection.encryptedPassphrase
        ? EncryptionService.decrypt(connection.encryptedPassphrase)
        : undefined;

      return {
        userUid: connection.userUid,
        exchange: connection.exchange,
        label: connection.label,
        apiKey,
        apiSecret,
        passphrase,
        isActive: connection.isActive,
      };
    } catch (error) {
      logger.error('Failed to decrypt credentials:', error);
      return null;
    }
  }

  async updateConnection(id: string, updates: Partial<ExchangeCredentials>): Promise<ExchangeConnection> {
    const updateData: any = {};

    if (updates.label) {
updateData.label = updates.label;
}
    if (updates.isActive !== undefined) {
updateData.isActive = updates.isActive;
}

    if (updates.apiKey) {
      updateData.encryptedApiKey = EncryptionService.encrypt(updates.apiKey);
    }
    if (updates.apiSecret) {
      updateData.encryptedApiSecret = EncryptionService.encrypt(updates.apiSecret);
    }
    if (updates.passphrase) {
      updateData.encryptedPassphrase = EncryptionService.encrypt(updates.passphrase);
    }

    // Update credentials hash if any credentials changed
    if (updates.apiKey || updates.apiSecret || updates.passphrase !== undefined) {
      const connection = await this.prisma.exchangeConnection.findUnique({
        where: { id },
      });

      if (connection) {
        const apiKey = updates.apiKey || EncryptionService.decrypt(connection.encryptedApiKey);
        const apiSecret = updates.apiSecret || EncryptionService.decrypt(connection.encryptedApiSecret);
        const passphrase = updates.passphrase !== undefined
          ? updates.passphrase
          : (connection.encryptedPassphrase ? EncryptionService.decrypt(connection.encryptedPassphrase) : undefined);

        updateData.credentialsHash = EncryptionService.createCredentialsHash(apiKey, apiSecret, passphrase);
      }
    }

    const updatedConnection = await this.prisma.exchangeConnection.update({
      where: { id },
      data: updateData,
    });

    return this.mapPrismaConnectionToConnection(updatedConnection);
  }

  async deleteConnection(id: string): Promise<void> {
    await this.prisma.exchangeConnection.delete({
      where: { id },
    });
  }

  /**
   * Get all user UIDs that have at least one active exchange connection
   * Used by scheduler to sync only active users
   */
  async getActiveUserUids(): Promise<string[]> {
    const result = await this.prisma.exchangeConnection.findMany({
      where: { isActive: true },
      select: { userUid: true },
      distinct: ['userUid'],
    });

    return result.map(item => item.userUid);
  }

  /**
   * Get all active connections with their sync intervals
   * Used by scheduler to create jobs with exchange-specific intervals
   * Returns: Array of {userUid, exchange, syncIntervalMinutes}
   */
  async getActiveConnectionsWithIntervals(): Promise<Array<{
    userUid: string;
    exchange: string;
    syncIntervalMinutes: number;
  }>> {
    const connections = await this.prisma.exchangeConnection.findMany({
      where: { isActive: true },
      select: {
        userUid: true,
        exchange: true,
        syncIntervalMinutes: true,
      },
    });

    return connections.map(conn => ({
      userUid: conn.userUid,
      exchange: conn.exchange,
      syncIntervalMinutes: conn.syncIntervalMinutes,
    }));
  }

  async findExistingConnection(userUid: string, exchange: string, label: string): Promise<ExchangeConnection | null> {
    const connection = await this.prisma.exchangeConnection.findFirst({
      where: {
        userUid,
        exchange,
        label,
        isActive: true,
      },
    });

    return connection ? this.mapPrismaConnectionToConnection(connection) : null;
  }

  async getUniqueCredentialsForUser(userUid: string): Promise<ExchangeConnection[]> {
    // Get all active connections for user
    const connections = await this.prisma.exchangeConnection.findMany({
      where: {
        userUid,
        isActive: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    // Filter by unique credentials hash
    const uniqueConnections: PrismaExchangeConnection[] = [];
    const seenHashes = new Set<string>();

    for (const connection of connections) {
      if (connection.credentialsHash && !seenHashes.has(connection.credentialsHash)) {
        seenHashes.add(connection.credentialsHash);
        uniqueConnections.push(connection);
      }
    }

    return uniqueConnections.map(this.mapPrismaConnectionToConnection);
  }

  async getConnectionsByCredentialsHash(userUid: string, credentialsHash: string): Promise<ExchangeConnection[]> {
    const connections = await this.prisma.exchangeConnection.findMany({
      where: {
        userUid,
        credentialsHash,
      },
      orderBy: { createdAt: 'desc' },
    });

    return connections.map(this.mapPrismaConnectionToConnection);
  }

  async countConnectionsByUser(userUid: string): Promise<number> {
    return this.prisma.exchangeConnection.count({
      where: { userUid, isActive: true },
    });
  }

  private mapPrismaConnectionToConnection(prismaConnection: PrismaExchangeConnection): ExchangeConnection {
    return {
      id: prismaConnection.id,
      userUid: prismaConnection.userUid,
      exchange: prismaConnection.exchange,
      label: prismaConnection.label,
      encryptedApiKey: prismaConnection.encryptedApiKey,
      encryptedApiSecret: prismaConnection.encryptedApiSecret,
      encryptedPassphrase: prismaConnection.encryptedPassphrase,
      credentialsHash: prismaConnection.credentialsHash,
      isActive: prismaConnection.isActive,
      createdAt: prismaConnection.createdAt,
      updatedAt: prismaConnection.updatedAt,
    };
  }
}