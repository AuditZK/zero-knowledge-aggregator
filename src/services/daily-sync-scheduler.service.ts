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
      // Get all users with active connections
      const users = await this.userRepo.getAllUsers();
      logger.info(`Found ${users.length} total users in database`);

      let totalSynced = 0;
      let totalFailed = 0;
      let usersWithPartialFailure = 0;

      for (const user of users) {
        try {
          // Get active connections for this user
          const connections = await this.exchangeConnectionRepo.getConnectionsByUser(user.uid, true);

          if (connections.length === 0) {
            logger.info(`User ${user.uid}: No active exchange connections, skipping`);
            continue;
          }

          logger.info(`User ${user.uid}: Found ${connections.length} active exchange(s), starting atomic sync`);

          // ATOMIC SYNC: Build ALL snapshots in memory first
          const snapshots: SnapshotData[] = [];
          const failedExchanges: string[] = [];

          for (const connection of connections) {
            try {
              // Build snapshot WITHOUT saving (memory only)
              const snapshot = await this.snapshotAggregator.buildSnapshot(user.uid, connection.exchange);

              if (snapshot) {
                snapshots.push(snapshot);
                logger.info(`User ${user.uid}/${connection.exchange}: Snapshot built successfully (pending atomic save)`);
              } else {
                failedExchanges.push(connection.exchange);
                logger.warn(`User ${user.uid}/${connection.exchange}: No snapshot returned (no connector)`);
              }

              // Small delay between exchanges to avoid overwhelming APIs
              await new Promise(resolve => setTimeout(resolve, 500));
            } catch (error) {
              failedExchanges.push(connection.exchange);
              logger.error(`User ${user.uid}/${connection.exchange}: Failed to build snapshot`, error);
            }
          }

          // ATOMIC SAVE: All-or-nothing per user
          if (failedExchanges.length > 0) {
            // At least one exchange failed - DO NOT save any snapshots for this user
            logger.error(`User ${user.uid}: ATOMIC SYNC ABORTED - ${failedExchanges.length}/${connections.length} exchanges failed`, {
              failed_exchanges: failedExchanges,
              successful_exchanges: snapshots.map(s => s.exchange),
              reason: 'Partial snapshots would corrupt performance metrics'
            });
            totalFailed += connections.length;
            usersWithPartialFailure++;
          } else if (snapshots.length > 0) {
            // ALL exchanges succeeded - save atomically
            try {
              await this.snapshotDataRepo.upsertSnapshotsTransactional(snapshots);
              logger.info(`User ${user.uid}: ATOMIC SYNC COMPLETED - ${snapshots.length} snapshots saved`, {
                exchanges: snapshots.map(s => s.exchange),
                total_equity: snapshots.reduce((sum, s) => sum + s.totalEquity, 0).toFixed(2)
              });
              totalSynced += snapshots.length;
            } catch (saveError) {
              logger.error(`User ${user.uid}: ATOMIC SAVE FAILED - transaction rolled back`, saveError);
              totalFailed += snapshots.length;
            }
          }
        } catch (error) {
          logger.error(`User ${user.uid}: Failed to process user`, error);
          totalFailed++;
        }
      }

      const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);

      logger.info('Daily sync completed', {
        snapshots_created: totalSynced,
        failed: totalFailed,
        users_with_partial_failure: usersWithPartialFailure,
        duration_sec: durationSec,
        completed_at: new Date().toISOString(),
        strategy: 'atomic_multi_exchange'
      });
    } catch (error) {
      logger.error('DAILY SYNC FAILED', error);
    } finally {
      this.isRunning = false;
    }
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
