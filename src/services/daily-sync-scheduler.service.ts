import { injectable, inject } from 'tsyringe';
import * as cron from 'node-cron';
import { UserRepository } from '../core/repositories/user-repository';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { EquitySnapshotAggregator } from './equity-snapshot-aggregator';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('DailySyncScheduler');

/**
 * Daily Sync Scheduler Service
 *
 * SECURITY: Runs inside AMD SEV-SNP enclave with hardware-attested clock
 * This ensures snapshot timestamps cannot be manipulated, providing verifiable proof
 * that equity snapshots are taken systematically at 00:00 UTC every day,
 * not cherry-picked at favorable market conditions.
 *
 * Architecture:
 * - Cron job executes at 00:00 UTC daily (strict schedule)
 * - Syncs ALL active users automatically (no rate limiting)
 * - Manual syncs via ProcessSyncJob are blocked after initialization
 * - All sync timestamps logged for audit trail
 * - Enclave attestation proves scheduler integrity
 */
@injectable()
export class DailySyncSchedulerService {
  private cronJob: cron.ScheduledTask | null = null;
  private isRunning = false;

  constructor(
    @inject(UserRepository) private readonly userRepo: UserRepository,
    @inject(ExchangeConnectionRepository) private readonly exchangeConnectionRepo: ExchangeConnectionRepository,
    @inject(EquitySnapshotAggregator) private readonly snapshotAggregator: EquitySnapshotAggregator
  ) {}

  /**
   * Start the daily sync scheduler
   *
   * Cron schedule: '0 0 * * *' = Every day at 00:00 UTC
   *
   * IMPORTANT: This scheduler runs in UTC timezone to ensure consistent
   * snapshot times across all deployments regardless of server location.
   */
  start(): void {
    if (this.cronJob) {
      logger.warn('Daily sync scheduler already running');
      return;
    }

    // Schedule: 00:00 UTC daily
    // Format: minute hour day month weekday
    this.cronJob = cron.schedule(
      '0 0 * * *',
      async () => {
        await this.executeDailySync();
      },
      {
        scheduled: true,
        timezone: 'UTC', // CRITICAL: Force UTC to prevent timezone manipulation
      }
    );

    logger.info('✅ Daily sync scheduler STARTED (executes at 00:00 UTC)');
    logger.info('⏰ Next sync at: ' + this.getNextSyncTime().toISOString());
  }

  /**
   * Stop the daily sync scheduler
   */
  stop(): void {
    if (this.cronJob) {
      this.cronJob.stop();
      this.cronJob = null;
      logger.info('Daily sync scheduler STOPPED');
    }
  }

  /**
   * Execute daily sync for all active users
   *
   * This method:
   * 1. Gets all active users from database
   * 2. For each user, syncs all their active exchange connections
   * 3. Creates snapshots without rate limiting (automatic execution)
   * 4. Logs all operations for audit trail
   */
  private async executeDailySync(): Promise<void> {
    if (this.isRunning) {
      logger.warn('Daily sync already in progress, skipping...');
      return;
    }

    this.isRunning = true;
    const startTime = Date.now();

    logger.info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    logger.info('🔒 DAILY SYNC STARTED (Enclave-Attested Timestamp: ' + new Date().toISOString() + ')');
    logger.info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    try {
      // Get all users with active connections
      const users = await this.userRepo.getAllUsers();
      logger.info(`Found ${users.length} total users in database`);

      let totalSynced = 0;
      let totalFailed = 0;

      for (const user of users) {
        try {
          // Get active connections for this user
          const connections = await this.exchangeConnectionRepo.getConnectionsByUser(user.uid, true);

          if (connections.length === 0) {
            logger.info(`User ${user.uid}: No active exchange connections, skipping`);
            continue;
          }

          logger.info(`User ${user.uid}: Found ${connections.length} active exchange(s)`);

          // Sync each exchange
          for (const connection of connections) {
            try {
              // Perform snapshot sync (no rate limiting for automatic daily syncs)
              await this.snapshotAggregator.updateCurrentSnapshot(user.uid, connection.exchange);

              logger.info(`✅ User ${user.uid}/${connection.exchange}: Snapshot created successfully`);
              totalSynced++;

              // Small delay between exchanges to avoid overwhelming APIs
              await new Promise(resolve => setTimeout(resolve, 500));
            } catch (error) {
              logger.error(`❌ User ${user.uid}/${connection.exchange}: Snapshot creation failed`, error);
              totalFailed++;
            }
          }
        } catch (error) {
          logger.error(`❌ User ${user.uid}: Failed to process user`, error);
          totalFailed++;
        }
      }

      const duration = ((Date.now() - startTime) / 1000).toFixed(2);

      logger.info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      logger.info('📊 DAILY SYNC SUMMARY:');
      logger.info(`   ✅ Snapshots created: ${totalSynced}`);
      logger.info(`   ❌ Failed: ${totalFailed}`);
      logger.info(`   ⏱️  Duration: ${duration}s`);
      logger.info(`   🕐 Completed at: ${new Date().toISOString()}`);
      logger.info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    } catch (error) {
      logger.error('❌ DAILY SYNC FAILED', error);
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Manual trigger for daily sync (admin use only)
   *
   * SECURITY WARNING: This bypasses the automatic schedule and should only
   * be used for testing or emergency scenarios. All manual triggers are logged.
   */
  async triggerManualSync(): Promise<void> {
    logger.warn('⚠️  MANUAL SYNC TRIGGERED (bypassing scheduler)');
    await this.executeDailySync();
  }

  /**
   * Get the next scheduled sync time
   */
  getNextSyncTime(): Date {
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
    tomorrow.setUTCHours(0, 0, 0, 0);
    return tomorrow;
  }

  /**
   * Get scheduler status
   */
  getStatus(): {
    isRunning: boolean;
    syncInProgress: boolean;
    nextSyncTime: Date;
  } {
    return {
      isRunning: this.cronJob !== null,
      syncInProgress: this.isRunning,
      nextSyncTime: this.getNextSyncTime(),
    };
  }
}
