import { injectable, inject } from 'tsyringe';
import { PrismaClient, SyncStatus as PrismaSyncStatus, SyncStatusEnum } from '@prisma/client';
import { SyncStatus } from '../../types';

@injectable()
export class SyncStatusRepository {
  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient,
  ) {}

  async upsertSyncStatus(status: Omit<SyncStatus, 'id' | 'createdAt' | 'updatedAt'>): Promise<SyncStatus> {
    const syncStatus = await this.prisma.syncStatus.upsert({
      where: {
        userUid_exchange: {
          userUid: status.userUid,
          exchange: status.exchange,
        },
      },
      update: {
        lastSyncTime: status.lastSyncTime,
        status: status.status as SyncStatusEnum,
        totalTrades: status.totalTrades,
        errorMessage: status.errorMessage,
        updatedAt: new Date(),
      },
      create: {
        userUid: status.userUid,
        exchange: status.exchange,
        lastSyncTime: status.lastSyncTime,
        status: status.status as SyncStatusEnum,
        totalTrades: status.totalTrades,
        errorMessage: status.errorMessage,
      },
    });

    return this.mapPrismaSyncStatusToSyncStatus(syncStatus);
  }

  async getSyncStatus(userUid: string, exchange: string): Promise<SyncStatus | null> {
    const syncStatus = await this.prisma.syncStatus.findUnique({
      where: {
        userUid_exchange: {
          userUid,
          exchange,
        },
      },
    });

    return syncStatus ? this.mapPrismaSyncStatusToSyncStatus(syncStatus) : null;
  }

  async getAllSyncStatuses(): Promise<SyncStatus[]> {
    const syncStatuses = await this.prisma.syncStatus.findMany({
      orderBy: { updatedAt: 'desc' },
    });

    return syncStatuses.map(this.mapPrismaSyncStatusToSyncStatus);
  }

  async getSyncStatusesByUser(userUid: string): Promise<SyncStatus[]> {
    const syncStatuses = await this.prisma.syncStatus.findMany({
      where: { userUid },
      orderBy: { updatedAt: 'desc' },
    });

    return syncStatuses.map(this.mapPrismaSyncStatusToSyncStatus);
  }

  async getPendingSyncs(): Promise<SyncStatus[]> {
    const syncStatuses = await this.prisma.syncStatus.findMany({
      where: {
        OR: [
          { status: SyncStatusEnum.pending },
          { status: SyncStatusEnum.syncing },
        ],
      },
      orderBy: { updatedAt: 'asc' },
    });

    return syncStatuses.map(this.mapPrismaSyncStatusToSyncStatus);
  }

  async getErrorSyncs(): Promise<SyncStatus[]> {
    const syncStatuses = await this.prisma.syncStatus.findMany({
      where: { status: SyncStatusEnum.error },
      orderBy: { updatedAt: 'desc' },
    });

    return syncStatuses.map(this.mapPrismaSyncStatusToSyncStatus);
  }

  async deleteSyncStatus(userUid: string, exchange: string): Promise<void> {
    await this.prisma.syncStatus.delete({
      where: {
        userUid_exchange: {
          userUid,
          exchange,
        },
      },
    });
  }

  async resetSyncStatus(userUid: string, exchange: string): Promise<SyncStatus> {
    const syncStatus = await this.prisma.syncStatus.update({
      where: {
        userUid_exchange: {
          userUid,
          exchange,
        },
      },
      data: {
        status: SyncStatusEnum.pending,
        lastSyncTime: null,
        errorMessage: null,
        updatedAt: new Date(),
      },
    });

    return this.mapPrismaSyncStatusToSyncStatus(syncStatus);
  }

  private mapPrismaSyncStatusToSyncStatus(prismaSyncStatus: PrismaSyncStatus): SyncStatus {
    return {
      id: prismaSyncStatus.id,
      userUid: prismaSyncStatus.userUid,
      exchange: prismaSyncStatus.exchange,
      lastSyncTime: prismaSyncStatus.lastSyncTime || undefined,
      status: prismaSyncStatus.status as 'pending' | 'syncing' | 'completed' | 'error',
      totalTrades: prismaSyncStatus.totalTrades,
      errorMessage: prismaSyncStatus.errorMessage || undefined,
      createdAt: prismaSyncStatus.createdAt,
      updatedAt: prismaSyncStatus.updatedAt,
    };
  }
}