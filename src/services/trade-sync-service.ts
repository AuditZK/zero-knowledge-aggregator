/**
 * TradeSyncService - Memory-Only Trade Processing
 *
 * SECURITY: Trades are NEVER persisted to database
 * - Fetches trades from exchange API
 * - Returns trade count for status tracking
 * - Individual trade data stays in memory only
 * - EquitySnapshotAggregator handles aggregation directly from API
 */

import { injectable, inject } from 'tsyringe';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { SyncStatusRepository } from '../core/repositories/sync-status-repository';
import { UserRepository } from '../core/repositories/user-repository';
import { ExchangeConnectorFactory } from '../external/factories/ExchangeConnectorFactory';
import { UniversalConnectorCacheService } from '../core/services/universal-connector-cache.service';
import { EncryptionService } from './encryption-service';
import { ExchangeCredentials } from '../types';
import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';
import { TimeUtils } from '../utils/time-utils';

const logger = getLogger('TradeSyncService');

@injectable()
export class TradeSyncService {
  constructor(
    @inject(ExchangeConnectionRepository) private readonly exchangeConnectionRepo: ExchangeConnectionRepository,
    @inject(SyncStatusRepository) private readonly syncStatusRepo: SyncStatusRepository,
    @inject(UserRepository) private readonly userRepo: UserRepository,
    @inject(UniversalConnectorCacheService) private readonly connectorCache: UniversalConnectorCacheService,
  ) {}

  private async ensureUser(userUid: string): Promise<void> {
    try {
      await this.userRepo.createUser({ uid: userUid });
    } catch (error: unknown) {
      const prismaError = error as { code?: string };
      if (prismaError.code !== 'P2002') { throw error; }
    }
  }

  /**
   * Fetch trade count from exchange (memory only - no persistence)
   * Used for status tracking and sync verification
   */
  private async fetchTradeCount(credentials: ExchangeCredentials, startDate: Date): Promise<number> {
    const exchange = credentials.exchange.toLowerCase();

    if (!ExchangeConnectorFactory.isSupported(exchange)) {
      throw new Error(`Exchange ${exchange} not supported`);
    }

    const connector = this.connectorCache.getOrCreate(exchange, credentials);
    const endDate = new Date();

    logger.info(`Fetching trades from ${startDate.toISOString()} to ${endDate.toISOString()}`);

    // Fetch trades in memory only - never persisted
    const trades = await connector.getTrades(startDate, endDate);

    // Return count only - individual trade data is discarded
    return trades.length;
  }

  private async testConnectionUnified(credentials: ExchangeCredentials): Promise<boolean> {
    const exchange = credentials.exchange.toLowerCase();

    if (!ExchangeConnectorFactory.isSupported(exchange)) {
      logger.error(`Exchange ${exchange} not supported`);
      return false;
    }

    const connector = this.connectorCache.getOrCreate(exchange, credentials);
    return await connector.testConnection();
  }

  async syncUserTrades(userUid: string): Promise<{ success: boolean; message: string; synced: number }> {
    try {
      await this.ensureUser(userUid);
      const tradeSyncResult = await this.syncTradesForStatistics(userUid);
      return {
        success: tradeSyncResult.success,
        message: `Sync completed: ${tradeSyncResult.synced} trades processed (memory only)`,
        synced: tradeSyncResult.synced,
      };
    } catch (error) {
      logger.error(`Sync failed for user ${userUid}`, error);
      const errorMessage = extractErrorMessage(error);
      return { success: false, message: `Sync failed: ${errorMessage}`, synced: 0 };
    }
  }

  /**
   * Sync exchange trades - MEMORY ONLY
   * Trades are fetched, counted, then discarded
   * Actual aggregation happens in EquitySnapshotAggregator
   */
  async syncExchangeTrades(userUid: string, connectionId: string): Promise<number> {
    const credentials = await this.exchangeConnectionRepo.getDecryptedCredentials(connectionId);
    if (!credentials) { throw new Error('Failed to get exchange credentials'); }

    await this.syncStatusRepo.upsertSyncStatus({
      userUid,
      exchange: credentials.exchange,
      lastSyncTime: new Date(),
      status: 'syncing',
      totalTrades: 0,
      errorMessage: undefined,
    });

    try {
      // Always sync from start of day (00:00 UTC) for daily snapshots
      const startOfDay = TimeUtils.getStartOfDayUTC();

      logger.info(`Daily sync for ${credentials.exchange} from ${startOfDay.toISOString()}`);

      // Fetch trade count only - trades stay in memory
      const tradeCount = await this.fetchTradeCount(credentials, startOfDay);

      await this.syncStatusRepo.upsertSyncStatus({
        userUid,
        exchange: credentials.exchange,
        lastSyncTime: new Date(),
        status: 'completed',
        totalTrades: tradeCount,
        errorMessage: undefined,
      });

      return tradeCount;
    } catch (error) {
      const errorMessage = extractErrorMessage(error);
      await this.syncStatusRepo.upsertSyncStatus({
        userUid,
        exchange: credentials.exchange,
        lastSyncTime: new Date(),
        status: 'error',
        totalTrades: 0,
        errorMessage,
      });
      throw error;
    }
  }

  async syncTradesForStatistics(userUid: string): Promise<{ success: boolean; synced: number; message: string }> {
    try {
      const uniqueConnections = (await this.exchangeConnectionRepo.getUniqueCredentialsForUser(userUid)) ?? [];
      if (uniqueConnections.length === 0) {
        return { success: false, synced: 0, message: 'No active exchange connections found' };
      }

      const totalConnections = (await this.exchangeConnectionRepo.getConnectionsByUser(userUid, true)) ?? [];
      const skippedDuplicates = totalConnections.length - uniqueConnections.length;

      const syncResults = await Promise.allSettled(
        uniqueConnections.map(connection =>
          this.syncExchangeTrades(userUid, connection.id).catch(error => {
            logger.error(`Failed to sync ${connection.exchange} (${connection.label})`, error);
            return 0;
          })
        )
      );

      const totalSynced = syncResults.reduce((sum, result) =>
        result.status === 'fulfilled' ? sum + result.value : sum, 0
      );

      return {
        success: true,
        synced: totalSynced,
        message: `Processed ${totalSynced} trades from ${uniqueConnections.length} exchanges (${skippedDuplicates} duplicates skipped)`,
      };
    } catch (error) {
      logger.error(`Sync failed for user ${userUid}`, error);
      const errorMessage = extractErrorMessage(error);
      return { success: false, synced: 0, message: `Sync failed: ${errorMessage}` };
    }
  }

  async syncAllUsers(): Promise<void> {
    try {
      const pendingSyncs = await this.syncStatusRepo.getAllSyncStatuses();
      for (const syncStatus of pendingSyncs) {
        try {
          await this.syncUserTrades(syncStatus.userUid);
          await new Promise(resolve => setTimeout(resolve, 2000));
        } catch (error) {
          logger.error(`Failed to sync user ${syncStatus.userUid}`, error);
        }
      }
    } catch (error) {
      logger.error('Failed to sync all users', error);
    }
  }

  async addExchangeConnection(
    userUid: string,
    exchange: string,
    label: string,
    apiKey: string,
    apiSecret: string,
    passphrase?: string
  ): Promise<{ success: boolean; message: string; connectionId?: string }> {
    try {
      await this.ensureUser(userUid);

      const existingConnection = await this.exchangeConnectionRepo.findExistingConnection(userUid, exchange, label);
      if (existingConnection) {
        return {
          success: false,
          message: `Connection for ${exchange} with label "${label}" already exists`,
        };
      }

      const credentialsHash = EncryptionService.createCredentialsHash(apiKey, apiSecret, passphrase);
      const sameCredentialsConnections = await this.exchangeConnectionRepo.getConnectionsByCredentialsHash(userUid, credentialsHash);
      if (sameCredentialsConnections.length > 0) {
        const existingLabels = sameCredentialsConnections.map(conn => conn.label).join(', ');
        logger.warn(`Adding duplicate credentials for ${exchange}`, { existingConnections: existingLabels });
      }

      const testCredentials = { userUid, exchange, label, apiKey, apiSecret, passphrase };
      const isValid = await this.testConnectionUnified(testCredentials);
      if (!isValid) {
        const needsPassphrase = ['bitget', 'coinbase', 'okx', 'kucoin'].includes(exchange);
        return {
          success: false,
          message: `Invalid API credentials for ${exchange}${needsPassphrase ? ' - verify passphrase' : ''}`,
        };
      }

      const connection = await this.exchangeConnectionRepo.createConnection(testCredentials);
      await this.syncStatusRepo.upsertSyncStatus({
        userUid,
        exchange,
        lastSyncTime: undefined,
        status: 'pending',
        totalTrades: 0,
        errorMessage: undefined,
      });

      return {
        success: true,
        message: 'Exchange connection added - snapshots will be created automatically',
        connectionId: connection.id,
      };
    } catch (error) {
      logger.error('Failed to add exchange connection', error);
      const errorMessage = extractErrorMessage(error);
      if (errorMessage.includes('UNIQUE constraint failed')) {
        return {
          success: false,
          message: `Connection for ${exchange} with label "${label}" already exists`,
        };
      }
      return { success: false, message: `Failed to add connection: ${errorMessage}` };
    }
  }
}
