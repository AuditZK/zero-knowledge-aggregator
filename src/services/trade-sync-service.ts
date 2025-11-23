import { injectable, inject, container } from 'tsyringe';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { SyncStatusRepository } from '../core/repositories/sync-status-repository';
import { TradeRepository } from '../core/repositories/trade-repository';
import { UserRepository } from '../core/repositories/user-repository';
import { CCXTService } from '../external/ccxt-service';
import { ExchangeConnectorFactory } from '../external/factories/ExchangeConnectorFactory';
import { EquitySnapshotAggregator } from './equity-snapshot-aggregator';
import { UniversalConnectorCacheService } from '../core/services/universal-connector-cache.service';
import { EncryptionService } from './encryption-service';
import { TradeData, SyncStatus, ExchangeCredentials } from '../types';
import { getLogger } from '../utils/logger.service';

const logger = getLogger('TradeSyncService');

@injectable()
export class TradeSyncService {
  constructor(
    @inject(ExchangeConnectionRepository) private readonly exchangeConnectionRepo: ExchangeConnectionRepository,
    @inject(SyncStatusRepository) private readonly syncStatusRepo: SyncStatusRepository,
    @inject(TradeRepository) private readonly tradeRepo: TradeRepository,
    @inject(UserRepository) private readonly userRepo: UserRepository,
    @inject(CCXTService) private readonly ccxtService: CCXTService,
    @inject(EquitySnapshotAggregator) private readonly equitySnapshotAggregator: EquitySnapshotAggregator,
    @inject(UniversalConnectorCacheService) private readonly connectorCache: UniversalConnectorCacheService,
  ) {}

  /**
   * Initialize services (create tables, etc.)
   */
  async initialize(): Promise<void> {
    // No initialization needed
  }

  /**
   * Fetch trades using connectors (new architecture) or CCXT (fallback)
   * This provides a unified interface for trade fetching
   * @param startDate - Optional start date for incremental sync. If not provided, fetches last 90 days.
   */
  private async fetchTradesUnified(credentials: ExchangeCredentials, startDate?: Date): Promise<TradeData[]> {
    const exchange = credentials.exchange.toLowerCase();

    // Try new connector architecture first
    if (ExchangeConnectorFactory.isSupported(exchange)) {
      logger.info(`Using ExchangeConnector for ${exchange}`);

      try {
        // OPTIMIZATION: Use UniversalConnectorCache for ALL connector types (CCXT + custom brokers)
        // Cache handles both crypto exchanges and stock brokers (IBKR, Alpaca) transparently
        const connector = this.connectorCache.getOrCreate(exchange, credentials);

        // Calculate date range
        const endDate = new Date();
        const fetchStartDate = startDate || new Date(Date.now() - 90 * 24 * 60 * 60 * 1000); // Default: 90 days ago

        logger.info(`Fetching trades from ${fetchStartDate.toISOString()} to ${endDate.toISOString()}`);

        const trades = await connector.getTrades(fetchStartDate, endDate);

        // Map connector TradeData to internal TradeData format
        return trades.map(trade => ({
          userUid: credentials.userUid || '',
          symbol: trade.symbol,
          type: trade.side, // 'buy' or 'sell'
          quantity: trade.quantity,
          price: trade.price,
          fees: trade.fee,
          timestamp: trade.timestamp,
          exchange: credentials.exchange,
          exchangeTradeId: trade.tradeId,
        }));

      } catch (error) {
        logger.error(`Connector failed for ${exchange}, falling back to CCXT`, error);
        // Fall through to CCXT if connector fails
      }
    }

    // Fallback to CCXT for unsupported exchanges or connector failures
    logger.info(`Using CCXT for ${exchange}`);
    return this.ccxtService.fetchAllHistoricalTrades(credentials, true);
  }

  /**
   * Test connection using connectors or CCXT
   */
  private async testConnectionUnified(credentials: ExchangeCredentials): Promise<boolean> {
    const exchange = credentials.exchange.toLowerCase();

    // Try new connector architecture first
    if (ExchangeConnectorFactory.isSupported(exchange)) {
      try {
        // OPTIMIZATION: Use UniversalConnectorCache for ALL connector types
        const connector = this.connectorCache.getOrCreate(exchange, credentials);
        return await connector.testConnection();
      } catch (error) {
        logger.error(`Connector test failed for ${exchange}, falling back to CCXT`, error);
        // Fall through to CCXT
      }
    }

    // Fallback to CCXT
    return this.ccxtService.testConnection(credentials);
  }

  async syncUserTrades(userUid: string): Promise<{ success: boolean; message: string; synced: number }> {
    try {
      // Ensure user exists in database to avoid foreign key constraint errors
      try {
        await this.userRepo.createUser({ uid: userUid });
      } catch (error: any) {
        // Ignore if user already exists (P2002 = unique constraint error)
        if (error.code !== 'P2002') {
          throw error;
        }
      }

      // Real-time sync only: Fetch new trades and update current snapshot
      const tradeSyncResult = await this.syncTradesForStatistics(userUid);

      // syncTradesForStatistics already calls updateCurrentSnapshot() internally
      // No historical recalculation - aggregator-basic handles real-time only

      return {
        success: tradeSyncResult.success,
        message: `Real-time sync completed: ${tradeSyncResult.synced} new trades synced, current snapshot updated`,
        synced: tradeSyncResult.synced,
      };

    } catch (error) {
      logger.error(`Real-time sync failed for user ${userUid}`, error);
      return {
        success: false,
        message: `Real-time sync failed: ${error.message}`,
        synced: 0,
      };
    }
  }

  async syncExchangeTrades(userUid: string, connectionId: string): Promise<number> {
    const credentials = await this.exchangeConnectionRepo.getDecryptedCredentials(connectionId);

    if (!credentials) {
      throw new Error('Failed to get exchange credentials');
    }

    // Update sync status to "syncing"
    await this.syncStatusRepo.upsertSyncStatus({
      userUid,
      exchange: credentials.exchange,
      lastSyncTime: new Date(),
      status: 'syncing',
      totalTrades: 0,
      errorMessage: null,
      
    });

    try {
      // Database-first approach: Check last trade timestamp instead of sync status
      // SIMPLIFIED AGGREGATOR V1: Always fetch only last 2 hours (no historical management)
      // Historical reconstruction is handled by Analytics Service
      const bufferHours = 2;
      const now = new Date();
      const startDate = new Date(now.getTime() - (bufferHours * 60 * 60 * 1000));

      const lastTradeTimestamp = await this.tradeRepo.getLastTradeTimestamp(userUid, credentials.exchange);
      const isFirstSync = !lastTradeTimestamp;

      if (isFirstSync) {
        logger.info(`First sync for ${credentials.exchange} - fetching last ${bufferHours}h only (no historical data)`);
      } else {
        logger.info(`Incremental sync for ${credentials.exchange} from ${startDate.toISOString()} to ${now.toISOString()}`);
      }

      const trades: TradeData[] = await this.fetchTradesUnified(credentials, startDate);

      if (trades.length === 0) {

        await this.syncStatusRepo.upsertSyncStatus({
          userUid,
          exchange: credentials.exchange,
          lastSyncTime: new Date(),
          status: 'completed',
          totalTrades: 0,
          errorMessage: null,
          
        });
        return 0;
      }

      // Optimize: Batch processing for better performance
      const tradeIds = trades.map(t => t.exchangeTradeId);
      const existingTradeIds = await this.tradeRepo.getExistingTradeIds(userUid, tradeIds);
      const newTrades = trades.filter(trade => !existingTradeIds.includes(trade.exchangeTradeId));

      let syncedCount = 0;

      if (newTrades.length > 0) {
        const createRequests = newTrades.map(trade => ({
          userUid: trade.userUid,
          symbol: trade.symbol,
          type: trade.type as any,
          quantity: trade.quantity,
          price: trade.price,
          fees: trade.fees,
          timestamp: trade.timestamp,
          exchange: credentials.exchange,
          exchangeTradeId: trade.exchangeTradeId,
        }));

        const insertedTrades = await this.tradeRepo.batchCreateTrades(createRequests);
        syncedCount = insertedTrades.length;

        // Trigger automatic trade matching and hourly aggregation for new trades
        if (insertedTrades.length > 0) {
          // Update current snapshot with market breakdown (real-time, not full recalculation)
          await this.equitySnapshotAggregator.updateCurrentSnapshot(userUid, credentials.exchange);
        }
      }

      // Update sync status to "completed"
      await this.syncStatusRepo.upsertSyncStatus({
        userUid,
        exchange: credentials.exchange,
        lastSyncTime: new Date(),
        status: 'completed',
        totalTrades: syncedCount,
        errorMessage: null,
      });

      return syncedCount;

    } catch (error) {
      // Update sync status with error
      await this.syncStatusRepo.upsertSyncStatus({
        userUid,
        exchange: credentials.exchange,
        lastSyncTime: new Date(),
        status: 'error',
        totalTrades: 0,
        errorMessage: error.message,
        
      });

      throw error;
    }
  }

  /**
   * NOUVEAU: Synchronise les trades uniquement pour les statistiques (volume/count)
   * Ne fait pas de FIFO matching, juste stockage pour agrégation horaire
   */
  async syncTradesForStatistics(userUid: string): Promise<{ success: boolean; synced: number; message: string }> {
    try {

      // Get unique connections based on credentials hash to avoid duplicate API calls
      const uniqueConnections = await this.exchangeConnectionRepo.getUniqueCredentialsForUser(userUid);

      if (uniqueConnections.length === 0) {
        return {
          success: false,
          synced: 0,
          message: 'No active exchange connections found for user',
        };
      }

      let totalSynced = 0;
      const totalConnections = await this.exchangeConnectionRepo.getConnectionsByUser(userUid, true);
      const skippedDuplicates = totalConnections.length - uniqueConnections.length;

      // Parallel execution: sync all exchanges concurrently for better performance
      // Previous: sequential sync took 9-24s for 3 exchanges
      // Now: parallel sync takes 3-8s (fastest exchange determines total time)
      const syncResults = await Promise.allSettled(
        uniqueConnections.map(connection =>
          this.syncExchangeTrades(userUid, connection.id)
            .catch(error => {
              logger.error(`Failed to sync trades from ${connection.exchange} (${connection.label})`, error);
              return 0; // Return 0 on error to not break the flow
            })
        )
      );

      // Aggregate results
      totalSynced = syncResults.reduce((sum, result) => {
        if (result.status === 'fulfilled') {
          return sum + result.value;
        }
        return sum;
      }, 0);

      if (skippedDuplicates > 0) {

      }

      return {
        success: totalSynced > 0,
        synced: totalSynced,
        message: `Synced ${totalSynced} trades for volume/quantity context from ${uniqueConnections.length} unique exchanges (${skippedDuplicates} duplicates skipped)`,
      };

    } catch (error) {
      logger.error(`Trade context sync failed for user ${userUid}`, error);
      return {
        success: false,
        synced: 0,
        message: `Trade context sync failed: ${error.message}`,
      };
    }
  }

  async syncAllUsers(): Promise<void> {
    try {

      // Get all sync statuses (mock - no getPendingSyncs method available)
      const pendingSyncs = await this.syncStatusRepo.getAllSyncStatuses();

      for (const syncStatus of pendingSyncs) {
        try {
          await this.syncUserTrades(syncStatus.userUid);

          // Rate limiting between users
          await this.sleep(2000);
        } catch (error) {
          logger.error(`Failed to sync user ${syncStatus.userUid}`, error);
        }
      }

    } catch (error) {
      logger.error('Failed to sync all users', error);
    }
  }

  async addExchangeConnection(userUid: string, exchange: string, label: string, apiKey: string, apiSecret: string, passphrase?: string): Promise<{ success: boolean; message: string; connectionId?: string }> {
    try {
      // Create user if doesn't exist
      try {
        await this.userRepo.createUser({ uid: userUid });
      } catch (error: any) {
        // Ignore if user already exists (P2002 = unique constraint error)
        if (error.code !== 'P2002') {
          throw error;
        }

      }

      // Check if connection already exists (same label)
      const existingConnection = await this.exchangeConnectionRepo.findExistingConnection(userUid, exchange, label);

      if (existingConnection) {
        return {
          success: false,
          message: `A connection for ${exchange} with label "${label}" already exists for this user. Please use a different label or update the existing connection.`,
        };
      }

      // Check if same credentials are already used (duplicate account detection)
      const credentialsHash = EncryptionService.createCredentialsHash(apiKey, apiSecret, passphrase);
      const sameCredentialsConnections = await this.exchangeConnectionRepo.getConnectionsByCredentialsHash(userUid, credentialsHash);

      if (sameCredentialsConnections.length > 0) {
        const existingLabels = sameCredentialsConnections.map(conn => conn.label).join(', ');
        logger.warn(`Adding duplicate credentials for ${exchange}`, { existingConnections: existingLabels });
        // Allow but warn - user might want multiple labels for the same account
      }

      // Test connection first
      const testCredentials = { userUid, exchange, label, apiKey, apiSecret, passphrase };
      const isValid = await this.testConnectionUnified(testCredentials);

      if (!isValid) {
        return {
          success: false,
          message: `Invalid API credentials for ${exchange} - connection test failed. Please verify your API key, secret${exchange === 'bitget' || exchange === 'coinbase' || exchange === 'okx' || exchange === 'kucoin' ? ', and passphrase' : ''}.`,
        };
      }

      // Store encrypted credentials
      const connection = await this.exchangeConnectionRepo.createConnection(testCredentials);

      // Initialize sync status as "pending" (no automatic sync)
      await this.syncStatusRepo.upsertSyncStatus({
        userUid,
        exchange,
        lastSyncTime: undefined,
        status: 'pending',
        totalTrades: 0,
        errorMessage: null,
        
      });

      return {
        success: true,
        message: 'Exchange connection added successfully - use sync endpoint to fetch and aggregate historical account data',
        connectionId: connection.id,
      };

    } catch (error) {
      logger.error('Failed to add exchange connection', error);

      // Handle unique constraint violation specifically
      if (error.message?.includes('UNIQUE constraint failed')) {
        return {
          success: false,
          message: `A connection for ${exchange} with label "${label}" already exists for this user. Please use a different label or update the existing connection.`,
        };
      }

      return {
        success: false,
        message: `Failed to add exchange connection: ${error.message}`,
      };
    }
  }

  async syncHistoricalTrades(userUid: string, exchange?: string): Promise<{ success: boolean; message: string; synced: number }> {
    try {

      // Ensure user exists in database to avoid foreign key constraint errors
      try {
        await this.userRepo.createUser({ uid: userUid });
      } catch (error: any) {
        // Ignore if user already exists (P2002 = unique constraint error)
        if (error.code !== 'P2002') {
          throw error;
        }

      }

      // Get exchange connections to sync
      const connections = await this.exchangeConnectionRepo.getConnectionsByUser(userUid, true);
      const connectionsToSync = exchange
        ? connections.filter(c => c.exchange === exchange)
        : connections;

      if (connectionsToSync.length === 0) {
        return {
          success: false,
          message: `No active exchange connections found${exchange ? ` for ${exchange}` : ''}`,
          synced: 0,
        };
      }

      let totalSynced = 0;

      for (const connection of connectionsToSync) {
        try {
          const synced = await this.syncHistoricalExchangeTrades(userUid, connection.id);
          totalSynced += synced;

        } catch (error) {
          logger.error(`Failed to sync historical trades from ${connection.exchange}`, error);

          // Update sync status with error
          await this.syncStatusRepo.upsertSyncStatus({
            userUid,
            exchange: connection.exchange,
            lastSyncTime: new Date(),
            status: 'error',
            totalTrades: 0,
            errorMessage: `Historical sync failed: ${error.message}`,
            
          });
        }
      }

      return {
        success: true,
        message: `Historical sync completed for ${connectionsToSync.length} exchange(s)`,
        synced: totalSynced,
      };

    } catch (error) {
      logger.error(`Historical trade sync failed for user ${userUid}`, error);
      return {
        success: false,
        message: `Historical trade sync failed: ${error.message}`,
        synced: 0,
      };
    }
  }

  async syncHistoricalExchangeTrades(userUid: string, connectionId: string): Promise<number> {
    const credentials = await this.exchangeConnectionRepo.getDecryptedCredentials(connectionId);

    if (!credentials) {
      throw new Error('Failed to get exchange credentials');
    }

    // Update sync status to "syncing"
    await this.syncStatusRepo.upsertSyncStatus({
      userUid,
      exchange: credentials.exchange,
      lastSyncTime: new Date(),
      status: 'syncing',
      totalTrades: 0,
      errorMessage: null,
      
    });

    try {

      // Force historical sync - get ALL trades (with active symbols filtering)
      const trades = await this.fetchTradesUnified(credentials);

      if (trades.length === 0) {

        await this.syncStatusRepo.upsertSyncStatus({
          userUid,
          exchange: credentials.exchange,
          lastSyncTime: new Date(),
          status: 'completed',
          totalTrades: 0,
          errorMessage: null,
          
        });
        return 0;
      }

      // Optimize: Batch check for existing trades
      const tradeIds = trades.map(t => t.exchangeTradeId);
      const existingTradeIds = await this.tradeRepo.getExistingTradeIds(userUid, tradeIds);

      // Filter out existing trades
      const newTrades = trades.filter(trade => !existingTradeIds.includes(trade.exchangeTradeId));

      let syncedCount = 0;

      if (newTrades.length > 0) {
        // Optimize: Batch insert trades in chunks to avoid memory issues
        const chunkSize = 100;
        const chunks = this.chunkArray(newTrades, chunkSize);

        for (let i = 0; i < chunks.length; i++) {
          const chunk = chunks[i];
          try {
            const createRequests = chunk.map(trade => ({
              userUid: trade.userUid,
              symbol: trade.symbol,
              type: trade.type as any,
              quantity: trade.quantity,
              price: trade.price,
              fees: trade.fees,
              timestamp: trade.timestamp,
              exchange: credentials.exchange,
              exchangeTradeId: trade.exchangeTradeId,
            }));

            const insertedTrades = await this.tradeRepo.batchCreateTrades(createRequests);
            syncedCount += insertedTrades.length;

            // Process trade matching and trigger hourly aggregation for this chunk
            if (insertedTrades.length > 0) {
              // Process matching for each trade in this chunk
              // Position-based: trades stored for volume/quantity context only

              // Position-based returns will be calculated after position sync
            }

          } catch (error) {
            logger.error(`Failed to insert trade chunk ${i + 1}`, error);
            // Continue with other chunks
          }
        }
      }

      // Update sync status to "completed" with historical complete flag
      await this.syncStatusRepo.upsertSyncStatus({
        userUid,
        exchange: credentials.exchange,
        lastSyncTime: new Date(),
        status: 'completed',
        totalTrades: syncedCount,
        errorMessage: null,
        
      });

      return syncedCount;

    } catch (error) {
      // Update sync status with error
      await this.syncStatusRepo.upsertSyncStatus({
        userUid,
        exchange: credentials.exchange,
        lastSyncTime: new Date(),
        status: 'error',
        totalTrades: 0,
        errorMessage: `Historical sync error: ${error.message}`,
        
      });

      throw error;
    }
  }

  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * REMOVED: Position-based approach doesn't need trade-based hourly aggregation
   * Returns are calculated directly from position closures
   */
}