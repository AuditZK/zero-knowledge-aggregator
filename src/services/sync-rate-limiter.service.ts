import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('SyncRateLimiter');

/**
 * Rate Limiter for Daily Sync Operations
 *
 * SECURITY: Prevents abuse by enforcing a minimum 23-hour interval between syncs
 * for the same user/exchange combination.
 *
 * Architecture:
 * - Stores last sync timestamp in database (SyncRateLimitLog table)
 * - Enforces 23-hour cooldown (allows 1-hour buffer for scheduling flexibility)
 * - Returns audit-friendly error messages when rate limit is hit
 * - Automatically cleans up old logs (retention: 7 days)
 */
@injectable()
export class SyncRateLimiterService {
  private readonly RATE_LIMIT_HOURS = 23; // Minimum hours between syncs
  private readonly LOG_RETENTION_DAYS = 7; // Keep logs for audit trail

  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient,
  ) {}

  /**
   * Check if a sync is allowed for the given user/exchange combination
   *
   * @param userUid - User identifier
   * @param exchange - Exchange name (e.g., 'binance', 'ibkr')
   * @returns Object with { allowed: boolean, reason?: string, nextAllowedTime?: Date }
   */
  async checkRateLimit(
    userUid: string,
    exchange: string,
  ): Promise<{ allowed: boolean; reason?: string; nextAllowedTime?: Date }> {
    try {
      // Get last sync time for this user/exchange
      const lastSync = await this.prisma.syncRateLimitLog.findUnique({
        where: {
          userUid_exchange: {
            userUid,
            exchange,
          },
        },
      });

      if (!lastSync) {
        // First sync for this user/exchange - always allowed
        logger.info(`Rate limit check PASSED for ${userUid}/${exchange} (first sync)`);
        return { allowed: true };
      }

      // Calculate time since last sync
      const now = new Date();
      const timeSinceLastSync = now.getTime() - lastSync.lastSyncTime.getTime();
      const hoursSinceLastSync = timeSinceLastSync / (1000 * 60 * 60);

      // Check if cooldown period has passed
      if (hoursSinceLastSync >= this.RATE_LIMIT_HOURS) {
        logger.info(`Rate limit check PASSED for ${userUid}/${exchange} (${hoursSinceLastSync.toFixed(1)}h since last sync)`);
        return { allowed: true };
      }

      // Rate limit exceeded - calculate next allowed time
      const nextAllowedTime = new Date(
        lastSync.lastSyncTime.getTime() + (this.RATE_LIMIT_HOURS * 60 * 60 * 1000)
      );

      const hoursRemaining = (this.RATE_LIMIT_HOURS - hoursSinceLastSync).toFixed(1);
      const reason = `Rate limit exceeded. Last sync was ${hoursSinceLastSync.toFixed(1)}h ago. Please wait ${hoursRemaining}h before next sync. Next allowed time: ${nextAllowedTime.toISOString()}`;

      logger.warn(`Rate limit check FAILED for ${userUid}/${exchange}: ${reason}`);

      return {
        allowed: false,
        reason,
        nextAllowedTime,
      };
    } catch (error) {
      logger.error(`Rate limit check error for ${userUid}/${exchange}`, error);
      // On error, allow sync (fail-open for availability)
      return { allowed: true };
    }
  }

  /**
   * Record a successful sync operation
   *
   * @param userUid - User identifier
   * @param exchange - Exchange name
   */
  async recordSync(userUid: string, exchange: string): Promise<void> {
    try {
      await this.prisma.syncRateLimitLog.upsert({
        where: {
          userUid_exchange: {
            userUid,
            exchange,
          },
        },
        update: {
          lastSyncTime: new Date(),
          syncCount: { increment: 1 },
        },
        create: {
          userUid,
          exchange,
          lastSyncTime: new Date(),
          syncCount: 1,
        },
      });

      logger.info(`Recorded sync for ${userUid}/${exchange}`);
    } catch (error) {
      logger.error(`Failed to record sync for ${userUid}/${exchange}`, error);
    }
  }

  /**
   * Clean up old rate limit logs (for privacy and database hygiene)
   * Should be called periodically (e.g., daily cron job)
   */
  async cleanupOldLogs(): Promise<number> {
    try {
      const cutoffDate = new Date(
        Date.now() - (this.LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000)
      );

      const result = await this.prisma.syncRateLimitLog.deleteMany({
        where: {
          lastSyncTime: {
            lt: cutoffDate,
          },
        },
      });

      if (result.count > 0) {
        logger.info(`Cleaned up ${result.count} old rate limit logs (older than ${this.LOG_RETENTION_DAYS} days)`);
      }

      return result.count;
    } catch (error) {
      logger.error('Failed to clean up old rate limit logs', error);
      return 0;
    }
  }

  /**
   * Get rate limit statistics for a user
   *
   * @param userUid - User identifier
   * @returns Array of sync logs with exchange, last sync time, and total sync count
   */
  async getUserRateLimitStats(userUid: string): Promise<Array<{
    exchange: string;
    lastSyncTime: Date;
    syncCount: number;
  }>> {
    try {
      const logs = await this.prisma.syncRateLimitLog.findMany({
        where: { userUid },
        orderBy: { lastSyncTime: 'desc' },
      });

      return logs.map(log => ({
        exchange: log.exchange,
        lastSyncTime: log.lastSyncTime,
        syncCount: log.syncCount,
      }));
    } catch (error) {
      logger.error(`Failed to get rate limit stats for ${userUid}`, error);
      return [];
    }
  }

  /**
   * Override rate limit for emergency manual sync (admin use only)
   *
   * @param userUid - User identifier
   * @param exchange - Exchange name
   */
  async overrideRateLimit(userUid: string, exchange: string): Promise<void> {
    try {
      await this.prisma.syncRateLimitLog.delete({
        where: {
          userUid_exchange: {
            userUid,
            exchange,
          },
        },
      });

      logger.warn(`Rate limit OVERRIDDEN for ${userUid}/${exchange} (manual admin action)`);
    } catch (error) {
      logger.error(`Failed to override rate limit for ${userUid}/${exchange}`, error);
    }
  }
}
