import { injectable, inject } from 'tsyringe';
import * as cron from 'node-cron';
import { UserRepository } from '../core/repositories/user-repository';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { SnapshotDataRepository } from '../core/repositories/snapshot-data-repository';
import { EquitySnapshotAggregator } from './equity-snapshot-aggregator';
import { getLogger } from '../utils/secure-enclave-logger';
import type { SnapshotData } from '../types';

const logger = getLogger('DailySyncScheduler');

/** Daily sync at 00:00 UTC inside AMD SEV-SNP enclave. Timestamps cannot be manipulated. */
@injectable()
export class DailySyncSchedulerService {
  private cronJob: cron.ScheduledTask | null = null;
  private isRunning = false;

  constructor(
    @inject(UserRepository) private readonly userRepo: UserRepository,
    @inject(ExchangeConnectionRepository) private readonly exchangeConnectionRepo: ExchangeConnectionRepository,
    @inject(EquitySnapshotAggregator) private readonly snapshotAggregator: EquitySnapshotAggregator,
    @inject(SnapshotDataRepository) private readonly snapshotDataRepo: SnapshotDataRepository
  ) {}

  /** Start cron scheduler (00:00 UTC daily). */
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
        timezone: 'UTC', // CRITICAL: Force UTC to prevent timezone manipulation
      }
    );

    logger.info('Daily sync scheduler STARTED (executes at 00:00 UTC)');
    logger.info('Next sync at: ' + this.getNextSyncTime().toISOString());
  }

  stop(): void {
    if (this.cronJob) {
      this.cronJob.stop();
      this.cronJob = null;
      logger.info('Daily sync scheduler STOPPED');
    }
  }

  /** Atomic sync: all exchanges succeed or none saved (prevents partial snapshots). */
  private async executeDailySync(): Promise<void> {
    if (this.isRunning) {
      logger.warn('Daily sync already in progress, skipping...');
      return;
    }

    this.isRunning = true;
    const startTime = Date.now();

    logger.info('Daily sync started', {
      timestamp: new Date().toISOString(),
      mode: 'enclave_attested',
      strategy: 'atomic_multi_exchange'
    });

    try {
      const stats = await this.syncAllUsers();
      this.logSyncCompletion(stats, startTime);
    } catch (error) {
      logger.error('DAILY SYNC FAILED', error);
    } finally {
      this.isRunning = false;
    }
  }

  private async syncAllUsers() {
    const users = await this.userRepo.getAllUsers();
    logger.info(`Found ${users.length} total users in database`);

    const stats = { totalSynced: 0, totalFailed: 0, usersWithPartialFailure: 0 };

    for (const user of users) {
      const result = await this.syncUserExchanges(user.uid);
      stats.totalSynced += result.synced;
      stats.totalFailed += result.failed;
      if (result.partialFailure) stats.usersWithPartialFailure++;
    }

    return stats;
  }

  private async syncUserExchanges(userUid: string): Promise<{ synced: number; failed: number; partialFailure: boolean }> {
    try {
      const connections = await this.exchangeConnectionRepo.getConnectionsByUser(userUid, true);

      if (connections.length === 0) {
        logger.info(`User ${userUid}: No active exchange connections, skipping`);
        return { synced: 0, failed: 0, partialFailure: false };
      }

      logger.info(`User ${userUid}: Found ${connections.length} active exchange(s), starting atomic sync`);

      const { snapshots, failedExchanges } = await this.buildUserSnapshots(userUid, connections);

      return this.saveUserSnapshots(userUid, snapshots, failedExchanges, connections.length);
    } catch (error) {
      logger.error(`User ${userUid}: Failed to process user`, error);
      return { synced: 0, failed: 1, partialFailure: false };
    }
  }

  private async buildUserSnapshots(userUid: string, connections: Array<{ exchange: string }>) {
    const snapshots: SnapshotData[] = [];
    const failedExchanges: string[] = [];

    for (const connection of connections) {
      const snapshot = await this.buildExchangeSnapshot(userUid, connection.exchange);
      if (snapshot) {
        snapshots.push(snapshot);
      } else {
        failedExchanges.push(connection.exchange);
      }
      // Small delay between exchanges to avoid overwhelming APIs
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    return { snapshots, failedExchanges };
  }

  private async buildExchangeSnapshot(userUid: string, exchange: string): Promise<SnapshotData | null> {
    try {
      const snapshot = await this.snapshotAggregator.buildSnapshot(userUid, exchange);
      if (snapshot) {
        logger.info(`User ${userUid}/${exchange}: Snapshot built successfully (pending atomic save)`);
        return snapshot;
      }
      logger.warn(`User ${userUid}/${exchange}: No snapshot returned (no connector)`);
      return null;
    } catch (error) {
      logger.error(`User ${userUid}/${exchange}: Failed to build snapshot`, error);
      return null;
    }
  }

  private async saveUserSnapshots(
    userUid: string,
    snapshots: SnapshotData[],
    failedExchanges: string[],
    totalConnections: number
  ): Promise<{ synced: number; failed: number; partialFailure: boolean }> {
    if (failedExchanges.length > 0) {
      logger.error(`User ${userUid}: ATOMIC SYNC ABORTED - ${failedExchanges.length}/${totalConnections} exchanges failed`, {
        failed_exchanges: failedExchanges,
        successful_exchanges: snapshots.map(s => s.exchange),
        reason: 'Partial snapshots would corrupt performance metrics'
      });
      return { synced: 0, failed: totalConnections, partialFailure: true };
    }

    if (snapshots.length === 0) {
      return { synced: 0, failed: 0, partialFailure: false };
    }

    try {
      await this.snapshotDataRepo.upsertSnapshotsTransactional(snapshots);
      logger.info(`User ${userUid}: ATOMIC SYNC COMPLETED - ${snapshots.length} snapshots saved`, {
        exchanges: snapshots.map(s => s.exchange),
        total_equity: snapshots.reduce((sum, s) => sum + s.totalEquity, 0).toFixed(2)
      });
      return { synced: snapshots.length, failed: 0, partialFailure: false };
    } catch (saveError) {
      logger.error(`User ${userUid}: ATOMIC SAVE FAILED - transaction rolled back`, saveError);
      return { synced: 0, failed: snapshots.length, partialFailure: false };
    }
  }

  private logSyncCompletion(stats: { totalSynced: number; totalFailed: number; usersWithPartialFailure: number }, startTime: number) {
    const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);
    logger.info('Daily sync completed', {
      snapshots_created: stats.totalSynced,
      failed: stats.totalFailed,
      users_with_partial_failure: stats.usersWithPartialFailure,
      duration_sec: durationSec,
      completed_at: new Date().toISOString(),
      strategy: 'atomic_multi_exchange'
    });
  }

  /** Admin-only manual trigger. Bypasses schedule, logged for audit. */
  async triggerManualSync(): Promise<void> {
    logger.warn('MANUAL SYNC TRIGGERED (bypassing scheduler)');
    await this.executeDailySync();
  }

  getNextSyncTime(): Date {
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
    tomorrow.setUTCHours(0, 0, 0, 0);
    return tomorrow;
  }

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
