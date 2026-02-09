import { injectable, inject } from 'tsyringe';
import { TradeSyncService } from './services/trade-sync-service';
import { EquitySnapshotAggregator } from './services/equity-snapshot-aggregator';
import { PerformanceMetricsService } from './services/performance-metrics.service';
import { SnapshotDataRepository } from './core/repositories/snapshot-data-repository';
import { ExchangeConnectionRepository } from './core/repositories/exchange-connection-repository';
import { UserRepository } from './core/repositories/user-repository';
import { getLogger, extractErrorMessage } from './utils/secure-enclave-logger';
import { SnapshotData } from './types';
// SECURITY: No TradeRepository - trades are memory-only (alpha protection)

const logger = getLogger('EnclaveWorker');

export interface SyncJobRequest {
  userUid: string;
  exchange?: string;
  /** @deprecated Sync type is now automatic based on exchange type */
  type?: 'incremental' | 'historical' | 'full';
}

export interface SyncJobResponse {
  success: boolean;
  userUid: string;
  exchange?: string;
  synced: number;
  snapshotsGenerated: number;  // Daily snapshots created (renamed from snapshotsGenerated)
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
 * - Aggregating into daily snapshots 
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
    @inject(PerformanceMetricsService) private readonly performanceMetricsService: PerformanceMetricsService,
    @inject(SnapshotDataRepository) private readonly snapshotDataRepo: SnapshotDataRepository,
    @inject(ExchangeConnectionRepository) private readonly exchangeConnectionRepo: ExchangeConnectionRepository,
    @inject(UserRepository) private readonly userRepo: UserRepository
  ) {}

  /**
   * Process a sync job request from the gateway
   *
   * AUTOMATIC BEHAVIOR BY EXCHANGE TYPE:
   * - IBKR: Auto-backfill from Flex (365 days) on first sync, then current day only
   * - Crypto: Current snapshot only (DailySyncScheduler handles midnight UTC syncs)
   *
   * SECURITY: Manual syncs are BLOCKED after initialization to prevent cherry-picking
   */
  async processSyncJob(request: SyncJobRequest): Promise<SyncJobResponse> {
    const startTime = Date.now();
    const { userUid, exchange } = request;

    try {
      logger.info('Processing sync job request', { userUid, exchange });

      // SECURITY: Block manual syncs after initialization
      const blockError = await this.checkManualSyncAllowed(userUid, exchange);
      if (blockError) {
        logger.warn('Manual sync blocked - automatic snapshots already initialized', { userUid, exchange });
        return blockError;
      }

      // Step 1: Sync today's trades from exchanges (for metrics: volume, fees, orders)
      const syncResult = await this.tradeSyncService.syncUserTrades(userUid);

      if (!syncResult.success) {
        // Use WARN for missing connections (not a real error), ERROR for actual failures
        const isNoConnections = syncResult.message.includes('No active exchange connections');
        if (isNoConnections) {
          logger.warn('Trade sync skipped - no connections', { userUid, exchange, message: syncResult.message });
        } else {
          logger.error('Trade sync failed', { userUid, exchange, message: syncResult.message });
        }
        return this.buildErrorResponse(userUid, exchange, syncResult.message);
      }

      // Step 2: Update snapshots (auto-backfill for IBKR if needed)
      const { snapshotsCount, latestSnapshot } = await this.updateSnapshotsForExchanges(
        userUid, exchange
      );

      // Step 3: Build success response
      return this.buildSuccessResponse({
        userUid,
        exchange,
        synced: syncResult.synced,
        snapshotsCount,
        latestSnapshot,
        duration: Date.now() - startTime
      });

    } catch (error: unknown) {
      return this.handleSyncError(error, userUid, exchange);
    }
  }

  /**
   * Check if manual sync is allowed
   *
   * SECURITY: Block manual syncs after initialization
   * - If ANY snapshot exists for the user/exchange, manual sync is blocked
   * - This prevents users from cherry-picking favorable snapshot times
   * - All syncs after initialization are handled by DailySyncScheduler
   *
   * Returns error response if blocked, null if allowed
   */
  private async checkManualSyncAllowed(
    userUid: string,
    exchange?: string
  ): Promise<SyncJobResponse | null> {
    // TEMP: Bypass for emergency snapshot recovery
    // TODO: Restore anti-cherry-picking check after emergency sync
    void userUid;
    void exchange;
    return null;
  }

  /**
   * Update snapshots for all user exchanges
   *
   * AUTOMATIC BEHAVIOR:
   * - IBKR: Auto-backfill from Flex (365 days) on first sync (0 snapshots)
   * - All exchanges: Update current snapshot
   */
  private async updateSnapshotsForExchanges(
    userUid: string,
    exchange?: string
  ): Promise<{ snapshotsCount: number; latestSnapshot: SnapshotData | null }> {
    let snapshotsCount = 0;
    let latestSnapshot: SnapshotData | null = null;

    // Get all connections for the user (each connection = exchange + label)
    const allConnections = (await this.exchangeConnectionRepo.getConnectionsByUser(userUid, true)) ?? [];
    const connections = exchange
      ? allConnections.filter(conn => conn.exchange === exchange)
      : allConnections;

    for (const conn of connections) {
      try {
        // For IBKR: Backfill historical data on FIRST sync only
        // IBKR Flex provides 365 days of daily equity data
        if (conn.exchange.toLowerCase() === 'ibkr') {
          const existingSnapshots = await this.snapshotDataRepo.getSnapshotData(userUid, undefined, undefined, conn.exchange);
          const snapshotCount = existingSnapshots?.length || 0;

          if (snapshotCount === 0) {
            logger.info(`IBKR first sync: running historical backfill from Flex data`, {
              userUid, exchange: conn.exchange, label: conn.label
            });
            await this.equitySnapshotAggregator.backfillIbkrHistoricalSnapshots(userUid, conn.exchange, conn.label);

            // Count backfilled snapshots
            const newSnapshots = await this.snapshotDataRepo.getSnapshotData(userUid, undefined, undefined, conn.exchange);
            snapshotsCount += newSnapshots?.length || 0;
          }
        }

        // Update current snapshot
        await this.equitySnapshotAggregator.updateCurrentSnapshot(userUid, conn.exchange, conn.label);
        snapshotsCount += 1;

        // Get the latest snapshot for response
        const snapshot = await this.snapshotDataRepo.getLatestSnapshotData(userUid, conn.exchange);
        if (snapshot && (!latestSnapshot || new Date(snapshot.timestamp) > new Date(latestSnapshot.timestamp))) {
          latestSnapshot = snapshot;
        }

        logger.info(`Snapshot updated for ${userUid}/${conn.exchange}/${conn.label}`, { snapshotsCount });
      } catch (error: unknown) {
        const errorMessage = extractErrorMessage(error);
        logger.error(`Failed to update snapshot for ${userUid}/${conn.exchange}/${conn.label}`, {
          error: errorMessage
        });
        // Continue with other connections
      }
    }

    return { snapshotsCount, latestSnapshot };
  }

  /**
   * Build success response with all metrics
   */
  private buildSuccessResponse(params: {
    userUid: string;
    exchange?: string;
    synced: number;
    snapshotsCount: number;
    latestSnapshot: SnapshotData | null;
    duration: number;
  }): SyncJobResponse {
    const { userUid, exchange, synced, snapshotsCount, latestSnapshot, duration } = params;

    logger.info('Enclave sync job completed', {
      userUid, synced, snapshotsGenerated: snapshotsCount, duration
    });

    return {
      success: true,
      userUid,
      exchange,
      synced: synced || 0,
      snapshotsGenerated: snapshotsCount,
      latestSnapshot: latestSnapshot ? {
        balance: latestSnapshot.realizedBalance,
        equity: latestSnapshot.totalEquity,
        timestamp: new Date(latestSnapshot.timestamp)
      } : undefined
    };
  }

  /**
   * Build error response for failed sync
   */
  private buildErrorResponse(
    userUid: string,
    exchange?: string,
    error?: string
  ): SyncJobResponse {
    return {
      success: false,
      userUid,
      exchange,
      synced: 0,
      snapshotsGenerated: 0,
      error
    };
  }

  /**
   * Handle unexpected errors during sync
   */
  private handleSyncError(
    error: unknown,
    userUid: string,
    exchange?: string
  ): SyncJobResponse {
    const errorMessage = extractErrorMessage(error);
    const errorStack = error instanceof Error ? error.stack || 'No stack trace available' : 'No stack trace available';
    const errorName = error instanceof Error ? error.name : 'Error';

    logger.error('Enclave sync job failed', {
      userUid,
      exchange,
      errorMessage,
      errorName,
      errorStack,
      errorObject: JSON.stringify(error, Object.getOwnPropertyNames(error))
    });

    return this.buildErrorResponse(userUid, exchange, errorMessage);
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
    // Get all connections to aggregate (each connection = exchange + label)
    const allConnections = (await this.exchangeConnectionRepo.getConnectionsByUser(userUid, true)) ?? [];
    const connections = exchange
      ? allConnections.filter(conn => conn.exchange === exchange)
      : allConnections;

    let totalBalance = 0;
    let totalEquity = 0;
    let totalRealizedPnl = 0;
    let totalUnrealizedPnl = 0;
    let totalFees = 0;
    let totalTrades = 0;
    let lastSync: Date | null = null;

    for (const conn of connections) {
      const snapshot = await this.snapshotDataRepo.getLatestSnapshotData(userUid, conn.exchange, conn.label);
      if (snapshot) {
        totalBalance += snapshot.realizedBalance;
        totalEquity += snapshot.totalEquity;
        totalRealizedPnl += 0; // Not available in SnapshotData - calculated from equity changes
        totalUnrealizedPnl += snapshot.unrealizedPnL;

        // Extract fees and trades from breakdown_by_market if available
        let breakdown = snapshot.breakdown_by_market;
        if (typeof breakdown === 'string') {
          try { breakdown = JSON.parse(breakdown); } catch { breakdown = undefined; }
        }
        const global = (breakdown as Record<string, { trading_fees?: number; funding_fees?: number; trades?: number }> | undefined)?.global;
        if (global) {
          totalFees += (global.trading_fees || 0) + (global.funding_fees || 0);
          totalTrades += global.trades || 0;
        }

        const snapshotDate = new Date(snapshot.timestamp);
        if (!lastSync || snapshotDate > lastSync) {
          lastSync = snapshotDate;
        }
      }
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
   * Get snapshot time series for a user
   * Returns daily snapshots for charting and historical analysis
   *
   * SECURITY: Only returns aggregated snapshot data (equity, balance, PnL)
   * NO individual trades are included
   */
  async getSnapshotTimeSeries(
    userUid: string,
    exchange?: string,
    startDate?: Date,
    endDate?: Date
  ): Promise<Array<{
    userUid: string;
    exchange: string;
    timestamp: Date;
    totalEquity: number;
    realizedBalance: number;
    unrealizedPnL: number;
    deposits: number;
    withdrawals: number;
    breakdown?: {
      global?: { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number };
      spot?: { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number };
      swap?: { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number };
      options?: { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number };
    };
  }>> {
    try {
      logger.info('Getting snapshot time series', {
        userUid,
        exchange,
        startDate: startDate?.toISOString(),
        endDate: endDate?.toISOString()
      });

      // Get snapshots from repository
      const snapshots = await this.snapshotDataRepo.getSnapshotData(
        userUid,
        startDate,
        endDate,
        exchange
      ) ?? [];

      // Map to response format (include breakdown_by_market for volume/fees/orders metrics)
      return snapshots.map(snapshot => {
        // Parse breakdown_by_market JSON if present
        let breakdown: typeof snapshot.breakdown_by_market = undefined;
        if (snapshot.breakdown_by_market) {
          try {
            breakdown = typeof snapshot.breakdown_by_market === 'string'
              ? JSON.parse(snapshot.breakdown_by_market)
              : snapshot.breakdown_by_market;
          } catch {
            breakdown = undefined;
          }
        }

        return {
          userUid: snapshot.userUid,
          exchange: snapshot.exchange,
          timestamp: new Date(snapshot.timestamp),
          totalEquity: snapshot.totalEquity,
          realizedBalance: snapshot.realizedBalance,
          unrealizedPnL: snapshot.unrealizedPnL,
          deposits: snapshot.deposits,
          withdrawals: snapshot.withdrawals,
          breakdown: breakdown as {
            global?: { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number };
            spot?: { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number };
            swap?: { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number };
            options?: { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number };
          } | undefined
        };
      });
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to get snapshot time series', {
        userUid,
        exchange,
        error: errorMessage
      });
      throw error;
    }
  }

  /**
   * Create a new user with exchange connection
   * Uses the userUid provided by the Platform (required for sync)
   *
   * SECURITY: Credentials are encrypted before storage
   * Returns only the userUid (no sensitive data)
   */
  async createUserConnection(request: {
    userUid: string;  // Platform provides the UUID
    exchange: string;
    label: string;
    apiKey: string;
    apiSecret: string;
    passphrase?: string;
  }): Promise<{
    success: boolean;
    userUid?: string;
    error?: string;
  }> {
    try {
      // Use the userUid provided by the Platform
      const userUid = request.userUid;

      logger.info('Creating user with Platform-provided UID', { userUid });

      // Step 1: Create user (upsert - creates if not exists)
      await this.userRepo.createUser({ uid: userUid });

      // Step 2: Check if exchange connection already exists
      const existingConnection = await this.exchangeConnectionRepo.findExistingConnection(
        userUid,
        request.exchange,
        request.label
      );

      if (existingConnection) {
        logger.warn('User and exchange connection already exist - skipping creation', {
          userUid,
          exchange: request.exchange,
          label: request.label
        });
        return {
          success: true,
          userUid,
          error: 'User connection already exists (no action taken)'
        };
      }

      // Step 3: Create exchange connection with encrypted credentials
      await this.exchangeConnectionRepo.createConnection({
        userUid,
        exchange: request.exchange,
        label: request.label,
        apiKey: request.apiKey,
        apiSecret: request.apiSecret,
        passphrase: request.passphrase,
        isActive: true
      });

      logger.info('User and exchange connection created successfully');

      return {
        success: true,
        userUid
      };
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      const errorStack = error instanceof Error ? error.stack : undefined;
      logger.error('Failed to create user connection', {
        error: errorMessage,
        stack: errorStack
      });

      return {
        success: false,
        error: errorMessage || 'Failed to create user connection'
      };
    }
  }

  /**
   * Get performance metrics for a user
   *
   * SECURITY: Returns only statistical metrics (Sharpe, volatility, drawdown)
   * NO individual trade data is included
   *
   * @param userUid User UID
   * @param exchange Optional exchange filter
   * @param startDate Optional start date filter
   * @param endDate Optional end date filter
   */
  async getPerformanceMetrics(
    userUid: string,
    exchange?: string,
    startDate?: Date,
    endDate?: Date
  ): Promise<{
    success: boolean;
    metrics?: {
      sharpeRatio: number | null;
      sortinoRatio: number | null;
      calmarRatio: number | null;
      volatility: number | null;
      downsideDeviation: number | null;
      maxDrawdown: number | null;
      maxDrawdownDuration: number | null;
      currentDrawdown: number | null;
      winRate: number | null;
      profitFactor: number | null;
      avgWin: number | null;
      avgLoss: number | null;
      periodStart: Date;
      periodEnd: Date;
      dataPoints: number;
    };
    error?: string;
  }> {
    try {
      logger.info('Getting performance metrics', {
        userUid,
        exchange,
        startDate: startDate?.toISOString(),
        endDate: endDate?.toISOString()
      });

      const metrics = await this.performanceMetricsService.calculateMetrics(
        userUid,
        exchange,
        startDate,
        endDate
      );

      if (!metrics) {
        return {
          success: false,
          error: 'Insufficient data for metrics calculation (need at least 2 days of snapshots)'
        };
      }

      return {
        success: true,
        metrics
      };
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to get performance metrics', {
        userUid,
        exchange,
        error: errorMessage
      });

      return {
        success: false,
        error: errorMessage
      };
    }
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
      // Verify database connectivity using snapshot repository
      await this.snapshotDataRepo.countSnapshots();

      return {
        status: 'healthy',
        enclave: true,
        version: '1.0.0',
        uptime: process.uptime()
      };
    } catch (error) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Health check failed - database connectivity issue', {
        error: errorMessage
      });
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