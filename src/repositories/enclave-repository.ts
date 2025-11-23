import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { Trade, HourlyReturn, BalanceSnapshot, ExchangeConnection } from '../types';
import { logger } from '../utils/logger';

/**
 * Enclave Repository
 *
 * Handles all database operations for the enclave worker.
 * - READ access to sensitive data (trades, encrypted credentials)
 * - WRITE access for aggregated, safe data (hourly_returns, balance_snapshots)
 *
 * CRITICAL: This repository is the ONLY way the enclave accesses the database.
 * Gateway MUST NOT have access to the methods that read individual trades.
 */
@injectable()
export class EnclaveRepository {
  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient
  ) {}

  // ============== SENSITIVE READ OPERATIONS (ENCLAVE ONLY) ==============

  /**
   * Get all trades for a specific user
   * ⚠️ ENCLAVE ONLY - Returns individual trades which are sensitive
   */
  async getTradesForUser(userUid: string, exchange?: string): Promise<Trade[]> {
    const where: any = { userUid };
    if (exchange) {
      where.exchange = exchange;
    }

    return await this.prisma.trade.findMany({
      where,
      orderBy: { timestamp: 'asc' }
    });
  }

  /**
   * Get trades within a specific time range
   * ⚠️ ENCLAVE ONLY - Returns individual trades
   */
  async getTradesInRange(
    userUid: string,
    startTime: Date,
    endTime: Date,
    exchange?: string
  ): Promise<Trade[]> {
    const where: any = {
      userUid,
      timestamp: {
        gte: startTime,
        lte: endTime
      }
    };
    if (exchange) {
      where.exchange = exchange;
    }

    return await this.prisma.trade.findMany({
      where,
      orderBy: { timestamp: 'asc' }
    });
  }

  /**
   * Get exchange connection with encrypted credentials
   * ⚠️ ENCLAVE ONLY - Contains encrypted API credentials
   */
  async getExchangeConnection(
    userUid: string,
    exchange: string
  ): Promise<ExchangeConnection | null> {
    return await this.prisma.exchangeConnection.findFirst({
      where: {
        userUid,
        exchange,
        isActive: true
      }
    });
  }

  /**
   * Get all active exchange connections for a user
   * ⚠️ ENCLAVE ONLY - Contains encrypted API credentials
   */
  async getUserExchangeConnections(userUid: string): Promise<ExchangeConnection[]> {
    return await this.prisma.exchangeConnection.findMany({
      where: {
        userUid,
        isActive: true
      }
    });
  }

  // ============== SAFE WRITE OPERATIONS (AGGREGATED DATA) ==============

  /**
   * Save hourly returns (aggregated data)
   * ✅ SAFE - Only aggregated metrics, no individual trades
   */
  async saveHourlyReturns(returns: HourlyReturn[]): Promise<void> {
    if (returns.length === 0) return;

    // Use upsert to handle duplicates
    for (const hourlyReturn of returns) {
      await this.prisma.hourlyReturn.upsert({
        where: {
          userUid_exchange_periodStart_periodEnd: {
            userUid: hourlyReturn.userUid,
            exchange: hourlyReturn.exchange,
            periodStart: hourlyReturn.periodStart,
            periodEnd: hourlyReturn.periodEnd
          }
        },
        update: {
          netReturn: hourlyReturn.netReturn,
          percentageReturn: hourlyReturn.percentageReturn,
          startingBalance: hourlyReturn.startingBalance,
          endingBalance: hourlyReturn.endingBalance,
          realizedPnl: hourlyReturn.realizedPnl,
          unrealizedPnl: hourlyReturn.unrealizedPnl,
          fees: hourlyReturn.fees,
          tradesCount: hourlyReturn.tradesCount,
          metadata: hourlyReturn.metadata as any,
          updatedAt: new Date()
        },
        create: hourlyReturn as any
      });
    }

    logger.info(`Saved ${returns.length} hourly returns`);
  }

  /**
   * Save balance snapshot
   * ✅ SAFE - Aggregated balance data
   */
  async saveBalanceSnapshot(snapshot: BalanceSnapshot): Promise<void> {
    await this.prisma.balanceSnapshot.create({
      data: snapshot as any
    });

    logger.info(`Saved balance snapshot for ${snapshot.userUid}/${snapshot.exchange}`);
  }

  /**
   * Batch save trades (from exchange sync)
   * ⚠️ ENCLAVE ONLY - Writing individual trades
   */
  async saveTrades(trades: Trade[]): Promise<void> {
    if (trades.length === 0) return;

    // Use createMany with skipDuplicates for efficiency
    const result = await this.prisma.trade.createMany({
      data: trades as any,
      skipDuplicates: true
    });

    logger.info(`Saved ${result.count} new trades (${trades.length - result.count} duplicates skipped)`);
  }

  /**
   * Update sync status
   * ✅ SAFE - Metadata about sync process
   */
  async updateSyncStatus(
    userUid: string,
    exchange: string,
    status: 'pending' | 'syncing' | 'completed' | 'failed',
    lastSyncedAt?: Date,
    error?: string
  ): Promise<void> {
    await this.prisma.syncStatus.upsert({
      where: {
        userUid_exchange: {
          userUid,
          exchange
        }
      },
      update: {
        status,
        lastSyncedAt: lastSyncedAt || new Date(),
        lastError: error,
        updatedAt: new Date()
      },
      create: {
        userUid,
        exchange,
        status,
        lastSyncedAt: lastSyncedAt || new Date(),
        lastError: error
      }
    });
  }

  // ============== HELPER METHODS ==============

  /**
   * Get latest balance snapshot for a user/exchange
   * ✅ SAFE - Aggregated data
   */
  async getLatestBalanceSnapshot(
    userUid: string,
    exchange: string
  ): Promise<BalanceSnapshot | null> {
    return await this.prisma.balanceSnapshot.findFirst({
      where: {
        userUid,
        exchange
      },
      orderBy: {
        timestamp: 'desc'
      }
    });
  }

  /**
   * Check if a trade already exists (for deduplication)
   * ⚠️ ENCLAVE ONLY - Queries individual trades
   */
  async tradeExists(exchangeTradeId: string, exchange: string): Promise<boolean> {
    const count = await this.prisma.trade.count({
      where: {
        exchangeTradeId,
        exchange
      }
    });
    return count > 0;
  }

  /**
   * Get trade count for a user in a time range
   * ✅ SAFE - Only returns count, not trade details
   */
  async getTradeCount(
    userUid: string,
    startTime: Date,
    endTime: Date,
    exchange?: string
  ): Promise<number> {
    const where: any = {
      userUid,
      timestamp: {
        gte: startTime,
        lte: endTime
      }
    };
    if (exchange) {
      where.exchange = exchange;
    }

    return await this.prisma.trade.count({ where });
  }
}

export default EnclaveRepository;