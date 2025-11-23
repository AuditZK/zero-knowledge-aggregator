import { injectable, inject } from 'tsyringe';
import { TradeSyncService } from './services/trade-sync-service';
import { EquitySnapshotAggregator } from './services/equity-snapshot-aggregator';
import { EnclaveRepository } from './repositories/enclave-repository';
import { logger } from './utils/logger';

export interface SyncJobRequest {
  userUid: string;
  exchange?: string;
  type: 'incremental' | 'historical' | 'full';
  startDate?: Date;
  endDate?: Date;
}

export interface SyncJobResponse {
  success: boolean;
  userUid: string;
  exchange?: string;
  synced: number;
  hourlyReturnsGenerated: number;
  latestSnapshot?: {
    balance: number;
    equity: number;
    timestamp: Date;
  };
  error?: string;
}

/**
 * Enclave Worker
 *
 * Main entry point for the enclave. Orchestrates all sensitive operations:
 * - Syncing trades from exchanges (using decrypted credentials)
 * - Processing individual trades
 * - Aggregating into hourly returns
 * - Returning only aggregated, safe data to the gateway
 *
 * CRITICAL: This worker runs inside the AMD SEV-SNP enclave.
 * It has access to sensitive data but only returns aggregated results.
 */
@injectable()
export class EnclaveWorker {
  constructor(
    @inject(TradeSyncService) private readonly tradeSyncService: TradeSyncService,
    @inject(EquitySnapshotAggregator) private readonly equitySnapshotAggregator: EquitySnapshotAggregator,
    @inject(EnclaveRepository) private readonly enclaveRepository: EnclaveRepository
  ) {}

  /**
   * Process a sync job request from the gateway
   * This is the main entry point for all sync operations
   */
  async processSyncJob(request: SyncJobRequest): Promise<SyncJobResponse> {
    const startTime = Date.now();
    const { userUid, exchange, type } = request;

    logger.info('Enclave processing sync job', {
      userUid,
      exchange,
      type
    });

    try {
      // Step 1: Sync trades from exchanges
      let syncResult;
      if (type === 'historical' && request.startDate && request.endDate) {
        syncResult = await this.tradeSyncService.syncHistoricalTrades(
          userUid,
          exchange,
          request.startDate,
          request.endDate
        );
      } else {
        syncResult = await this.tradeSyncService.syncUserTrades(userUid, exchange);
      }

      if (!syncResult.success) {
        return {
          success: false,
          userUid,
          exchange,
          synced: 0,
          hourlyReturnsGenerated: 0,
          error: syncResult.message
        };
      }

      // Step 2: Generate/update equity snapshots and hourly returns
      let hourlyReturnsCount = 0;
      let latestSnapshot = null;

      // Get all exchanges for the user if not specified
      const exchanges = exchange
        ? [exchange]
        : (await this.enclaveRepository.getUserExchangeConnections(userUid))
            .map(conn => conn.exchange);

      for (const ex of exchanges) {
        try {
          // Update current snapshot (which also generates hourly returns)
          await this.equitySnapshotAggregator.updateCurrentSnapshot(userUid, ex);

          // Get the latest snapshot for response
          const snapshot = await this.enclaveRepository.getLatestBalanceSnapshot(userUid, ex);
          if (snapshot && (!latestSnapshot || snapshot.timestamp > latestSnapshot.timestamp)) {
            latestSnapshot = snapshot;
          }

          // Count hourly returns generated
          const endTime = new Date();
          const startTime = new Date(endTime.getTime() - 24 * 60 * 60 * 1000); // Last 24h
          const count = await this.enclaveRepository.getTradeCount(userUid, startTime, endTime, ex);
          hourlyReturnsCount += Math.ceil(count / 60); // Rough estimate

          logger.info(`Updated snapshot and returns for ${userUid}/${ex}`);
        } catch (error: any) {
          logger.error(`Failed to update snapshot for ${userUid}/${ex}`, {
            error: error.message
          });
          // Continue with other exchanges
        }
      }

      const duration = Date.now() - startTime;
      logger.info('Enclave sync job completed', {
        userUid,
        synced: syncResult.synced || 0,
        hourlyReturnsGenerated: hourlyReturnsCount,
        duration
      });

      return {
        success: true,
        userUid,
        exchange,
        synced: syncResult.synced || 0,
        hourlyReturnsGenerated: hourlyReturnsCount,
        latestSnapshot: latestSnapshot ? {
          balance: latestSnapshot.totalBalance,
          equity: latestSnapshot.totalEquity,
          timestamp: latestSnapshot.timestamp
        } : undefined
      };

    } catch (error: any) {
      logger.error('Enclave sync job failed', {
        userUid,
        exchange,
        error: error.message,
        stack: error.stack
      });

      return {
        success: false,
        userUid,
        exchange,
        synced: 0,
        hourlyReturnsGenerated: 0,
        error: error.message
      };
    }
  }

  /**
   * Get aggregated metrics for a user
   * Returns only safe, aggregated data
   */
  async getAggregatedMetrics(
    userUid: string,
    exchange?: string
  ): Promise<{
    totalBalance: number;
    totalEquity: number;
    totalRealizedPnl: number;
    totalUnrealizedPnl: number;
    totalFees: number;
    totalTrades: number;
    lastSync: Date | null;
  }> {
    // Get exchanges to aggregate
    const exchanges = exchange
      ? [exchange]
      : (await this.enclaveRepository.getUserExchangeConnections(userUid))
          .map(conn => conn.exchange);

    let totalBalance = 0;
    let totalEquity = 0;
    let totalRealizedPnl = 0;
    let totalUnrealizedPnl = 0;
    let totalFees = 0;
    let totalTrades = 0;
    let lastSync: Date | null = null;

    for (const ex of exchanges) {
      const snapshot = await this.enclaveRepository.getLatestBalanceSnapshot(userUid, ex);
      if (snapshot) {
        totalBalance += snapshot.totalBalance;
        totalEquity += snapshot.totalEquity;
        totalRealizedPnl += snapshot.realizedPnl || 0;
        totalUnrealizedPnl += snapshot.unrealizedPnl || 0;
        totalFees += snapshot.totalFees || 0;

        if (!lastSync || snapshot.timestamp > lastSync) {
          lastSync = snapshot.timestamp;
        }
      }

      // Get trade count (safe - only returns count)
      const count = await this.enclaveRepository.getTradeCount(
        userUid,
        new Date(0), // All time
        new Date(),
        ex
      );
      totalTrades += count;
    }

    return {
      totalBalance,
      totalEquity,
      totalRealizedPnl,
      totalUnrealizedPnl,
      totalFees,
      totalTrades,
      lastSync
    };
  }

  /**
   * Health check for the enclave worker
   */
  async healthCheck(): Promise<{
    status: 'healthy' | 'unhealthy';
    enclave: boolean;
    version: string;
    uptime: number;
  }> {
    try {
      // Verify we can access the database
      await this.enclaveRepository.getTradeCount('test', new Date(), new Date());

      return {
        status: 'healthy',
        enclave: true,
        version: '1.0.0',
        uptime: process.uptime()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        enclave: true,
        version: '1.0.0',
        uptime: process.uptime()
      };
    }
  }
}

export default EnclaveWorker;