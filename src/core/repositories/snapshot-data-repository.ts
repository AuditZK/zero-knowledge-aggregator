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
        userUid_timestamp_exchange_label: {
          userUid: snapshot.userUid,
          timestamp: new Date(snapshot.timestamp),
          exchange: snapshot.exchange,
          label: snapshot.label || '',
        },
      },
      update: {
        totalEquity: snapshot.totalEquity,
        realizedBalance: snapshot.realizedBalance,
        unrealizedPnL: snapshot.unrealizedPnL,
        deposits: snapshot.deposits,
        withdrawals: snapshot.withdrawals,
        breakdown_by_market: (snapshot.breakdown_by_market || undefined) as Prisma.InputJsonValue,
        updatedAt: new Date(),
      },
      create: {
        userUid: snapshot.userUid,
        timestamp: new Date(snapshot.timestamp),
        exchange: snapshot.exchange,
        label: snapshot.label || '',
        totalEquity: snapshot.totalEquity,
        realizedBalance: snapshot.realizedBalance,
        unrealizedPnL: snapshot.unrealizedPnL,
        deposits: snapshot.deposits || 0,
        withdrawals: snapshot.withdrawals || 0,
        breakdown_by_market: (snapshot.breakdown_by_market || undefined) as Prisma.InputJsonValue,
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
      if (startDate) {where.timestamp.gte = startDate;}
      if (endDate) {where.timestamp.lte = endDate;}
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

  async getLatestSnapshotData(userUid: string, exchange?: string, label?: string): Promise<SnapshotData | null> {
    const where: Prisma.SnapshotDataWhereInput = { userUid };
    if (exchange) {
      where.exchange = exchange;
    }
    if (label !== undefined) {
      where.label = label;
    }

    const snapshotData = await this.prisma.snapshotData.findFirst({
      where,
      orderBy: { timestamp: 'desc' },
    });

    return snapshotData ? this.mapPrismaSnapshotDataToSnapshotData(snapshotData) : null;
  }

  async deleteSnapshotData(userUid: string, timestamp: string, exchange: string, label: string = ''): Promise<void> {
    await this.prisma.snapshotData.delete({
      where: {
        userUid_timestamp_exchange_label: {
          userUid,
          timestamp: new Date(timestamp),
          exchange,
          label,
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

  /**
   * Atomically upsert multiple snapshots in a single transaction.
   * If ANY snapshot fails, ALL are rolled back (all-or-nothing).
   *
   * SECURITY: Ensures multi-exchange users have complete snapshots.
   * Partial snapshots (missing exchanges) would corrupt performance metrics.
   */
  async upsertSnapshotsTransactional(
    snapshots: Array<Omit<SnapshotData, 'id' | 'createdAt' | 'updatedAt'>>
  ): Promise<SnapshotData[]> {
    if (snapshots.length === 0) {
      return [];
    }

    logger.info('Atomic snapshot upsert starting', {
      count: snapshots.length,
      exchanges: snapshots.map(s => s.exchange),
      userUid: snapshots[0]?.userUid
    });

    const results = await this.prisma.$transaction(
      snapshots.map(snapshot =>
        this.prisma.snapshotData.upsert({
          where: {
            userUid_timestamp_exchange_label: {
              userUid: snapshot.userUid,
              timestamp: new Date(snapshot.timestamp),
              exchange: snapshot.exchange,
              label: snapshot.label || '',
            },
          },
          update: {
            totalEquity: snapshot.totalEquity,
            realizedBalance: snapshot.realizedBalance,
            unrealizedPnL: snapshot.unrealizedPnL,
            deposits: snapshot.deposits,
            withdrawals: snapshot.withdrawals,
            breakdown_by_market: (snapshot.breakdown_by_market || undefined) as Prisma.InputJsonValue,
            updatedAt: new Date(),
          },
          create: {
            userUid: snapshot.userUid,
            timestamp: new Date(snapshot.timestamp),
            exchange: snapshot.exchange,
            label: snapshot.label || '',
            totalEquity: snapshot.totalEquity,
            realizedBalance: snapshot.realizedBalance,
            unrealizedPnL: snapshot.unrealizedPnL,
            deposits: snapshot.deposits || 0,
            withdrawals: snapshot.withdrawals || 0,
            breakdown_by_market: (snapshot.breakdown_by_market || undefined) as Prisma.InputJsonValue,
          },
        })
      )
    );

    logger.info('Atomic snapshot upsert completed', {
      count: results.length,
      userUid: snapshots[0]?.userUid
    });

    return results.map(this.mapPrismaSnapshotDataToSnapshotData);
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

  /**
   * Count total snapshots (used for health check database connectivity)
   */
  async countSnapshots(): Promise<number> {
    return await this.prisma.snapshotData.count();
  }

  async countSnapshotDataByUser(userUid: string, exchange?: string): Promise<number> {
    const where: Prisma.SnapshotDataWhereInput = { userUid };
    if (exchange) {
      where.exchange = exchange;
    }

    return this.prisma.snapshotData.count({ where });
  }

  /**
   * Check if any snapshot with non-zero equity exists for this user+exchange.
   * Used to detect first "real" snapshot (ignoring 0-equity API failures).
   */
  async hasNonZeroEquitySnapshot(userUid: string, exchange: string): Promise<boolean> {
    const snapshot = await this.prisma.snapshotData.findFirst({
      where: {
        userUid,
        exchange,
        totalEquity: { gt: 0 },
      },
      select: { id: true },
    });
    return snapshot !== null;
  }

  private mapPrismaSnapshotDataToSnapshotData(prismaSnapshotData: PrismaSnapshotData): SnapshotData {
    return {
      id: prismaSnapshotData.id,
      userUid: prismaSnapshotData.userUid,
      timestamp: prismaSnapshotData.timestamp.toISOString(),
      exchange: prismaSnapshotData.exchange,
      label: prismaSnapshotData.label,
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
