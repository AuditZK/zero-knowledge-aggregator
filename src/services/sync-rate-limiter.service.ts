import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('SyncRateLimiter');

/** 23-hour rate limit between syncs to prevent cherry-picking. Logs retained 7 days. */
@injectable()
export class SyncRateLimiterService {
  private readonly RATE_LIMIT_HOURS = 23; // Minimum hours between syncs
  private readonly LOG_RETENTION_DAYS = 7; // Keep logs for audit trail

  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient,
  ) {}

  /**
   * Check if a sync is allowed for the given user/exchange/label combination
   */
  async checkRateLimit(
    userUid: string,
    exchange: string,
    label: string = '',
  ): Promise<{ allowed: boolean; reason?: string; nextAllowedTime?: Date }> {
    try {
      const lastSync = await this.prisma.syncRateLimitLog.findUnique({
        where: {
          userUid_exchange_label: {
            userUid,
            exchange,
            label,
          },
        },
      });

      if (!lastSync) {
        logger.info(`Rate limit check PASSED for ${userUid}/${exchange}/${label} (first sync)`);
        return { allowed: true };
      }

      const now = new Date();
      const timeSinceLastSync = now.getTime() - lastSync.lastSyncTime.getTime();
      const hoursSinceLastSync = timeSinceLastSync / (1000 * 60 * 60);

      if (hoursSinceLastSync >= this.RATE_LIMIT_HOURS) {
        logger.info(`Rate limit check PASSED for ${userUid}/${exchange}/${label} (${hoursSinceLastSync.toFixed(1)}h since last sync)`);
        return { allowed: true };
      }

      const nextAllowedTime = new Date(
        lastSync.lastSyncTime.getTime() + (this.RATE_LIMIT_HOURS * 60 * 60 * 1000)
      );

      const hoursRemaining = (this.RATE_LIMIT_HOURS - hoursSinceLastSync).toFixed(1);
      const reason = `Rate limit exceeded. Last sync was ${hoursSinceLastSync.toFixed(1)}h ago. Please wait ${hoursRemaining}h before next sync. Next allowed time: ${nextAllowedTime.toISOString()}`;

      logger.warn(`Rate limit check FAILED for ${userUid}/${exchange}/${label}: ${reason}`);

      return {
        allowed: false,
        reason,
        nextAllowedTime,
      };
    } catch (error) {
      logger.error(`Rate limit check error for ${userUid}/${exchange}/${label}`, error);
      return { allowed: true };
    }
  }

  /**
   * Record a successful sync operation
   */
  async recordSync(userUid: string, exchange: string, label: string = ''): Promise<void> {
    try {
      await this.prisma.syncRateLimitLog.upsert({
        where: {
          userUid_exchange_label: {
            userUid,
            exchange,
            label,
          },
        },
        update: {
          lastSyncTime: new Date(),
          syncCount: { increment: 1 },
        },
        create: {
          userUid,
          exchange,
          label,
          lastSyncTime: new Date(),
          syncCount: 1,
        },
      });

      logger.info(`Recorded sync for ${userUid}/${exchange}/${label}`);
    } catch (error) {
      logger.error(`Failed to record sync for ${userUid}/${exchange}/${label}`, error);
    }
  }

  /**
   * Clean up old rate limit logs (for privacy and database hygiene)
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
   */
  async getUserRateLimitStats(userUid: string): Promise<Array<{
    exchange: string;
    label: string;
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
        label: log.label,
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
   */
  async overrideRateLimit(userUid: string, exchange: string, label: string = ''): Promise<void> {
    try {
      await this.prisma.syncRateLimitLog.delete({
        where: {
          userUid_exchange_label: {
            userUid,
            exchange,
            label,
          },
        },
      });

      logger.warn(`Rate limit OVERRIDDEN for ${userUid}/${exchange}/${label} (manual admin action)`);
    } catch (error) {
      logger.error(`Failed to override rate limit for ${userUid}/${exchange}/${label}`, error);
    }
  }
}
