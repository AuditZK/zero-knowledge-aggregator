import { injectable, inject } from 'tsyringe';
import { PrismaClient, SnapshotData as PrismaSnapshotData } from '@prisma/client';
import { SnapshotData } from '../../types';

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
        breakdown_by_market: snapshot.breakdown_by_market as any,
        updatedAt: new Date(),
      },
      create: {
        userUid: snapshot.userUid,
        timestamp: new Date(snapshot.timestamp),
        exchange: snapshot.exchange,
        breakdown_by_market: snapshot.breakdown_by_market as any,
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
    const where: any = { userUid };

    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) where.timestamp.gte = startDate;
      if (endDate) where.timestamp.lte = endDate;
    }

    if (exchange) {
      where.exchange = exchange;
      console.log('[SnapshotDataRepository] Filtering by exchange:', exchange);
    }

    console.log('[SnapshotDataRepository] Full where clause:', JSON.stringify(where, null, 2));
    console.log('[SnapshotDataRepository] userUid:', userUid);
    console.log('[SnapshotDataRepository] exchange param:', exchange);

    const snapshotData = await this.prisma.snapshotData.findMany({
      where,
      orderBy: { timestamp: 'desc' },
    });

    console.log('[SnapshotDataRepository] Found', snapshotData.length, 'snapshots');
    if (snapshotData.length > 0) {
      const exchanges = new Set(snapshotData.map(s => s.exchange));
      console.log('[SnapshotDataRepository] Exchanges in result:', Array.from(exchanges));
    }

    return snapshotData.map(this.mapPrismaSnapshotDataToSnapshotData);
  }

  async getSnapshotDataInRange(
    userUid: string,
    startTime: string,
    endTime: string,
    exchange?: string,
  ): Promise<SnapshotData[]> {
    const where: any = {
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
    const where: any = { userUid };
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
    const where: any = { userUid };
    if (exchange) {
      where.exchange = exchange;
    }

    const result = await this.prisma.snapshotData.deleteMany({
      where,
    });

    return result.count;
  }

  async countSnapshotDataByUser(userUid: string, exchange?: string): Promise<number> {
    const where: any = { userUid };
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
      breakdown_by_market: prismaSnapshotData.breakdown_by_market as any,
      createdAt: prismaSnapshotData.createdAt,
      updatedAt: prismaSnapshotData.updatedAt,
    };
  }
}
