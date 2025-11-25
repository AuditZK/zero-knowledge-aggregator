import { injectable, inject } from 'tsyringe';
import { PrismaClient, SnapshotData as PrismaSnapshotData, Prisma } from '@prisma/client';
import { SnapshotData, BreakdownByMarket } from '../../types';
import { getLogger } from '../../utils/secure-enclave-logger';

const logger = getLogger('SnapshotDataRepository');

@injectable()
export class SnapshotDataRepository {
  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient,
  ) {}

  async upsertSnapshotData(snapshot: Omit<SnapshotData, 'id' | 'createdAt' | 'updatedAt'>): Promise<SnapshotData> {
    const snapshotData = await this.prisma.snapshotData.upsert({
      where: {
        userUid_timestamp_exchange: {
          userUid: snapshot.userUid,
          timestamp: new Date(snapshot.timestamp),
          exchange: snapshot.exchange,
        },
      },
      update: {
        totalEquity: snapshot.totalEquity,
        realizedBalance: snapshot.realizedBalance,
        unrealizedPnL: snapshot.unrealizedPnL,
        deposits: snapshot.deposits,
        withdrawals: snapshot.withdrawals,
        breakdown_by_market: snapshot.breakdown_by_market as Prisma.JsonValue,
        updatedAt: new Date(),
      },
      create: {
        userUid: snapshot.userUid,
        timestamp: new Date(snapshot.timestamp),
        exchange: snapshot.exchange,
        totalEquity: snapshot.totalEquity,
        realizedBalance: snapshot.realizedBalance,
        unrealizedPnL: snapshot.unrealizedPnL,
        deposits: snapshot.deposits || 0,
        withdrawals: snapshot.withdrawals || 0,
        breakdown_by_market: snapshot.breakdown_by_market as Prisma.JsonValue,
      },
    });

    return this.mapPrismaSnapshotDataToSnapshotData(snapshotData);
  }

  async getSnapshotData(
    userUid: string,
    startDate?: Date,
    endDate?: Date,
    exchange?: string,
  ): Promise<SnapshotData[]> {
    const where: Prisma.SnapshotDataWhereInput = { userUid };

    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) where.timestamp.gte = startDate;
      if (endDate) where.timestamp.lte = endDate;
    }

    if (exchange) {
      where.exchange = exchange;
    }

    logger.debug('Querying snapshot data', {
      userUid,
      exchange,
      startDate: startDate?.toISOString(),
      endDate: endDate?.toISOString()
    });

    const snapshotData = await this.prisma.snapshotData.findMany({
      where,
      orderBy: { timestamp: 'desc' },
    });

    logger.debug('Snapshot data query completed', {
      count: snapshotData.length,
      exchanges: snapshotData.length > 0 ? Array.from(new Set(snapshotData.map(s => s.exchange))) : []
    });

    return snapshotData.map(this.mapPrismaSnapshotDataToSnapshotData);
  }

  async getSnapshotDataInRange(
    userUid: string,
    startTime: string,
    endTime: string,
    exchange?: string,
  ): Promise<SnapshotData[]> {
    const where: Prisma.SnapshotDataWhereInput = {
      userUid,
      timestamp: {
        gte: new Date(startTime),
        lte: new Date(endTime),
      },
    };

    if (exchange) {
      where.exchange = exchange;
    }

    const snapshotData = await this.prisma.snapshotData.findMany({
      where,
      orderBy: { timestamp: 'asc' },
    });

    return snapshotData.map(this.mapPrismaSnapshotDataToSnapshotData);
  }

  async getLatestSnapshotData(userUid: string, exchange?: string): Promise<SnapshotData | null> {
    const where: Prisma.SnapshotDataWhereInput = { userUid };
    if (exchange) {
      where.exchange = exchange;
    }

    const snapshotData = await this.prisma.snapshotData.findFirst({
      where,
      orderBy: { timestamp: 'desc' },
    });

    return snapshotData ? this.mapPrismaSnapshotDataToSnapshotData(snapshotData) : null;
  }

  async deleteSnapshotData(userUid: string, timestamp: string, exchange: string): Promise<void> {
    await this.prisma.snapshotData.delete({
      where: {
        userUid_timestamp_exchange: {
          userUid,
          timestamp: new Date(timestamp),
          exchange,
        },
      },
    });
  }

  async deleteOldData(beforeDate: Date): Promise<number> {
    const result = await this.prisma.snapshotData.deleteMany({
      where: {
        createdAt: { lt: beforeDate },
      },
    });

    return result.count;
  }

  async deleteAllForUser(userUid: string, exchange?: string): Promise<number> {
    const where: Prisma.SnapshotDataWhereInput = { userUid };
    if (exchange) {
      where.exchange = exchange;
    }

    const result = await this.prisma.snapshotData.deleteMany({
      where,
    });

    return result.count;
  }

  async countSnapshotDataByUser(userUid: string, exchange?: string): Promise<number> {
    const where: Prisma.SnapshotDataWhereInput = { userUid };
    if (exchange) {
      where.exchange = exchange;
    }

    return this.prisma.snapshotData.count({ where });
  }

  private mapPrismaSnapshotDataToSnapshotData(prismaSnapshotData: PrismaSnapshotData): SnapshotData {
    return {
      id: prismaSnapshotData.id,
      userUid: prismaSnapshotData.userUid,
      timestamp: prismaSnapshotData.timestamp.toISOString(),
      exchange: prismaSnapshotData.exchange,
      totalEquity: prismaSnapshotData.totalEquity,
      realizedBalance: prismaSnapshotData.realizedBalance,
      unrealizedPnL: prismaSnapshotData.unrealizedPnL,
      deposits: prismaSnapshotData.deposits,
      withdrawals: prismaSnapshotData.withdrawals,
      breakdown_by_market: prismaSnapshotData.breakdown_by_market as BreakdownByMarket | undefined,
      createdAt: prismaSnapshotData.createdAt,
      updatedAt: prismaSnapshotData.updatedAt,
    };
  }
}
