import { injectable, inject } from 'tsyringe';
import Bull from 'bull';
import { TradeSyncService } from '../../services/trade-sync-service';
import { EquitySnapshotAggregator } from '../../services/equity-snapshot-aggregator';
import { ExchangeConnectionRepository } from '../repositories/exchange-connection-repository';
import { logger } from '../../utils/logger';

export interface SyncJobData {
  userUid: string;
  exchange?: string;
  type: 'incremental' | 'historical' | 'full';
  priority?: number;
}

export interface SyncJobResult {
  userUid: string;
  success: boolean;
  synced: number;
  duration: number;
  error?: string;
}

/**
 * Queue-based synchronization service using Bull
 * Replaces the old polling-based scheduler
 */
@injectable()
export class SyncQueueService {
  private syncQueue: Bull.Queue<SyncJobData>;

  // Configuration
  private readonly CONCURRENCY = 5; // Process 5 jobs in parallel
  private readonly MAX_ATTEMPTS = 3;
  private readonly BACKOFF_DELAY = 5000; // 5 seconds

  constructor(
    @inject(TradeSyncService) private readonly tradeSyncService: TradeSyncService,
    @inject(EquitySnapshotAggregator) private readonly returnsService: EquitySnapshotAggregator,
    @inject(ExchangeConnectionRepository) private readonly exchangeConnectionRepo: ExchangeConnectionRepository,
    @inject('RedisUrl') redisUrl?: string,
  ) {
    // Initialize Bull queue with Redis
    this.syncQueue = new Bull<SyncJobData>('exchange-sync', redisUrl || 'redis://localhost:6379', {
      defaultJobOptions: {
        attempts: this.MAX_ATTEMPTS,
        backoff: {
          type: 'exponential',
          delay: this.BACKOFF_DELAY,
        },
        removeOnComplete: 100, // Keep last 100 completed jobs
        removeOnFail: 50, // Keep last 50 failed jobs
      },
    });

    this.setupEventHandlers();
  }

  /**
   * Setup queue event handlers for monitoring
   */
  private setupEventHandlers(): void {
    this.syncQueue.on('completed', (job, result: SyncJobResult) => {
      logger.info('Sync job completed', {
        jobId: job.id,
        userUid: result.userUid,
        synced: result.synced,
        duration: result.duration,
      });
    });

    this.syncQueue.on('failed', (job, err) => {
      logger.error('Sync job failed', {
        jobId: job.id,
        userUid: job.data.userUid,
        attempt: job.attemptsMade,
        error: err.message,
      });
    });

    this.syncQueue.on('stalled', (job) => {
      logger.warn('Sync job stalled', {
        jobId: job.id,
        userUid: job.data.userUid,
      });
    });

    this.syncQueue.on('active', (job) => {
      logger.debug('Sync job started', {
        jobId: job.id,
        userUid: job.data.userUid,
      });
    });
  }

  /**
   * Start processing sync jobs
   */
  async startWorkers(): Promise<void> {
    logger.info(`Starting sync queue workers with concurrency: ${this.CONCURRENCY}`);

    // Process sync jobs with concurrency
    this.syncQueue.process(this.CONCURRENCY, async (job) => {
      const startTime = Date.now();
      const { userUid, exchange, type } = job.data;

      try {
        logger.info('Processing sync job', {
          jobId: job.id,
          userUid,
          exchange,
          type,
        });

        // Update job progress
        await job.progress(10);

        // Perform the actual sync based on job type
        let result;
        if (type === 'historical') {
          result = await this.tradeSyncService.syncHistoricalTrades(userUid, exchange);
        } else {
          result = await this.tradeSyncService.syncUserTrades(userUid);
        }

        // Update job progress
        await job.progress(50);

        // CRITICAL: Snapshot current metrics (balance, equity, volume, trades, fees) for all exchanges
        // This must happen EVERY sync, even if no trades occurred
        try {
          const userConnections = await this.exchangeConnectionRepo.getConnectionsByUser(userUid, true);

          for (const conn of userConnections) {
            await this.returnsService.updateCurrentSnapshot(userUid, conn.exchange);
            logger.info(`Snapshotted metrics with breakdown for ${userUid} on ${conn.exchange}`);
          }
        } catch (snapshotError: any) {
          logger.error('Failed to snapshot metrics', {
            userUid,
            error: snapshotError.message,
          });
          // Don't throw - sync succeeded, snapshot is supplementary
        }

        // Update job progress
        await job.progress(100);

        const duration = Date.now() - startTime;

        return {
          userUid,
          success: result.success,
          synced: result.synced || 0,
          duration,
          error: result.success ? undefined : result.message,
        } as SyncJobResult;

      } catch (error: any) {
        logger.error('Sync job error', {
          jobId: job.id,
          userUid,
          error: error.message,
        });

        throw error; // Bull will handle retry
      }
    });

    logger.info('Sync queue workers started');
  }

  /**
   * Add a single user sync job to the queue
   */
  async addSyncJob(data: SyncJobData): Promise<Bull.Job<SyncJobData>> {
    const jobOptions: Bull.JobOptions = {
      priority: data.priority || 0,
      delay: 0,
    };

    const job = await this.syncQueue.add(data, jobOptions);

    logger.info('Sync job added to queue', {
      jobId: job.id,
      userUid: data.userUid,
      type: data.type,
    });

    return job;
  }

  /**
   * Schedule recurring sync for all active connections
   * Each exchange connection can have its own sync interval:
   * - IBKR (daily data): 1440 minutes (24 hours)
   * - Real-time exchanges: 60 minutes (1 hour)
   */
  async scheduleRecurringSyncs(): Promise<void> {
    logger.info('Scheduling recurring syncs with per-exchange intervals');

    // Get all active connections with their intervals
    const connections = await this.exchangeConnectionRepo.getActiveConnectionsWithIntervals();

    if (connections.length === 0) {
      logger.warn('No active connections found for scheduling');
      return;
    }

    // Group connections by interval to log summary
    const intervalGroups = new Map<number, number>();
    for (const conn of connections) {
      intervalGroups.set(conn.syncIntervalMinutes, (intervalGroups.get(conn.syncIntervalMinutes) || 0) + 1);
    }

    // Schedule a repeating job for each connection
    for (const conn of connections) {
      const jobId = `sync-${conn.userUid}-${conn.exchange}`;

      await this.syncQueue.add(
        {
          userUid: conn.userUid,
          exchange: conn.exchange,
          type: 'incremental',
        },
        {
          jobId, // Unique ID per user+exchange to prevent duplicates
          repeat: {
            every: conn.syncIntervalMinutes * 60 * 1000, // Convert to milliseconds
          },
        },
      );

      logger.debug(`Scheduled recurring sync for ${conn.userUid}/${conn.exchange} every ${conn.syncIntervalMinutes}min`);
    }

    // Log summary
    const summary = Array.from(intervalGroups.entries())
      .map(([interval, count]) => `${count} connections at ${interval}min`)
      .join(', ');
    logger.info(`Scheduled ${connections.length} recurring sync jobs: ${summary}`);
  }

  /**
   * Cancel recurring sync for a specific user
   */
  async cancelUserSync(userUid: string): Promise<void> {
    const jobId = `sync-${userUid}`;

    const repeatableJobs = await this.syncQueue.getRepeatableJobs();
    const job = repeatableJobs.find(j => j.id === jobId);

    if (job) {
      await this.syncQueue.removeRepeatableByKey(job.key);
      logger.info(`Cancelled recurring sync for user ${userUid}`);
    }
  }

  /**
   * Trigger immediate sync for all active users
   */
  async triggerFullSync(): Promise<void> {
    const activeUserUids = await this.exchangeConnectionRepo.getActiveUserUids();

    logger.info(`Triggering full sync for ${activeUserUids.length} users`);

    const jobs = await Promise.all(
      activeUserUids.map(userUid =>
        this.addSyncJob({
          userUid,
          type: 'full',
          priority: 1, // Higher priority for manual triggers
        }),
      ),
    );

    logger.info(`Added ${jobs.length} sync jobs to queue`);
  }

  /**
   * Get queue statistics
   */
  async getQueueStats(): Promise<{
    waiting: number;
    active: number;
    completed: number;
    failed: number;
    delayed: number;
    paused: boolean;
  }> {
    const [waiting, active, completed, failed, delayed, paused] = await Promise.all([
      this.syncQueue.getWaitingCount(),
      this.syncQueue.getActiveCount(),
      this.syncQueue.getCompletedCount(),
      this.syncQueue.getFailedCount(),
      this.syncQueue.getDelayedCount(),
      this.syncQueue.isPaused(),
    ]);

    return {
      waiting,
      active,
      completed,
      failed,
      delayed,
      paused,
    };
  }

  /**
   * Pause all job processing
   */
  async pause(): Promise<void> {
    await this.syncQueue.pause();
    logger.info('Sync queue paused');
  }

  /**
   * Resume job processing
   */
  async resume(): Promise<void> {
    await this.syncQueue.resume();
    logger.info('Sync queue resumed');
  }

  /**
   * Clean old completed and failed jobs
   */
  async cleanQueue(grace: number = 3600000): Promise<void> {
    await this.syncQueue.clean(grace); // Clean jobs older than 1 hour by default
    logger.info('Queue cleaned');
  }

  /**
   * Gracefully shutdown the queue
   */
  async shutdown(): Promise<void> {
    logger.info('Shutting down sync queue...');

    // Stop accepting new jobs
    await this.syncQueue.pause();

    // Wait for active jobs to complete (max 30 seconds)
    let attempts = 0;
    while (attempts < 30) {
      const activeCount = await this.syncQueue.getActiveCount();
      if (activeCount === 0) {
break;
}

      logger.info(`Waiting for ${activeCount} active jobs to complete...`);
      await new Promise(resolve => setTimeout(resolve, 1000));
      attempts++;
    }

    // Close the queue
    await this.syncQueue.close();
    logger.info('Sync queue shut down');
  }

  /**
   * Get the Bull queue instance (for dashboard)
   */
  getQueue(): Bull.Queue<SyncJobData> {
    return this.syncQueue;
  }
}

export default SyncQueueService;