import { injectable, inject } from 'tsyringe';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { SyncStatusRepository } from '../core/repositories/sync-status-repository';
import { TradeRepository } from '../core/repositories/trade-repository';
import { UserRepository } from '../core/repositories/user-repository';
import { ExchangeConnectorFactory } from '../external/factories/ExchangeConnectorFactory';
import { UniversalConnectorCacheService } from '../core/services/universal-connector-cache.service';
import { EncryptionService } from './encryption-service';
import { TradeData, ExchangeCredentials } from '../types';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('TradeSyncService');

@injectable()
export class TradeSyncService {
  constructor(
    @inject(ExchangeConnectionRepository) private readonly exchangeConnectionRepo: ExchangeConnectionRepository,
    @inject(SyncStatusRepository) private readonly syncStatusRepo: SyncStatusRepository,
    @inject(TradeRepository) private readonly tradeRepo: TradeRepository,
    @inject(UserRepository) private readonly userRepo: UserRepository,
    @inject(UniversalConnectorCacheService) private readonly connectorCache: UniversalConnectorCacheService,
  ) {}

  async initialize(): Promise<void> {}

  private async ensureUser(userUid: string): Promise<void> {
    try {
      await this.userRepo.createUser({ uid: userUid });
    } catch (error: unknown) {
      const prismaError = error as { code?: string };
      if (prismaError.code !== 'P2002') {throw error;}
    }
  }

  private async fetchTradesUnified(credentials: ExchangeCredentials, startDate?: Date): Promise<TradeData[]> {
    const exchange = credentials.exchange.toLowerCase();

    if (!ExchangeConnectorFactory.isSupported(exchange)) {
      throw new Error(`Exchange ${exchange} not supported. Supported exchanges: ${ExchangeConnectorFactory.getSupportedExchanges().join(', ')}`);
    }

    const connector = this.connectorCache.getOrCreate(exchange, credentials);
    const endDate = new Date();
    const fetchStartDate = startDate || new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    logger.info(`Fetching trades from ${fetchStartDate.toISOString()} to ${endDate.toISOString()}`);

    const trades = await connector.getTrades(fetchStartDate, endDate);
    return trades.map(trade => ({
      userUid: credentials.userUid || '',
      symbol: trade.symbol,
      type: trade.side,
      quantity: trade.quantity,
      price: trade.price,
      fees: trade.fee,
      timestamp: trade.timestamp,
      exchange: credentials.exchange,
      exchangeTradeId: trade.tradeId,
    }));
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
        message: `Real-time sync completed: ${tradeSyncResult.synced} new trades synced, current snapshot updated`,
        synced: tradeSyncResult.synced,
      };
    } catch (error) {
      logger.error(`Real-time sync failed for user ${userUid}`, error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      return { success: false, message: `Real-time sync failed: ${errorMessage}`, synced: 0 };
    }
  }

  async syncExchangeTrades(userUid: string, connectionId: string): Promise<number> {
    const credentials = await this.exchangeConnectionRepo.getDecryptedCredentials(connectionId);
    if (!credentials) {throw new Error('Failed to get exchange credentials');}

    await this.syncStatusRepo.upsertSyncStatus({
      userUid, exchange: credentials.exchange, lastSyncTime: new Date(),
      status: 'syncing', totalTrades: 0, errorMessage: undefined,
    });

    try {
      // Sync full day of trades (for daily snapshot metrics: volume, fees, order count)
      const now = new Date();
      const startOfDay = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
      const lastTradeTimestamp = await this.tradeRepo.getLastTradeTimestamp(userUid, credentials.exchange);
      const isFirstSync = !lastTradeTimestamp;

      // Use start of day for daily sync, or last trade timestamp if more recent
      const startDate = lastTradeTimestamp && lastTradeTimestamp > startOfDay ? lastTradeTimestamp : startOfDay;

      if (isFirstSync) {
        logger.info(`First sync for ${credentials.exchange} - fetching today's trades`);
      } else {
        logger.info(`Daily sync for ${credentials.exchange} from ${startDate.toISOString()}`);
      }

      const trades: TradeData[] = await this.fetchTradesUnified(credentials, startDate);

      if (trades.length === 0) {
        await this.syncStatusRepo.upsertSyncStatus({
          userUid, exchange: credentials.exchange, lastSyncTime: new Date(),
          status: 'completed', totalTrades: 0, errorMessage: undefined,
        });
        return 0;
      }

      const tradeIds = trades.map(t => t.exchangeTradeId);
      const existingTradeIds = await this.tradeRepo.getExistingTradeIds(userUid, tradeIds);
      const newTrades = trades.filter(trade => !existingTradeIds.includes(trade.exchangeTradeId));

      let syncedCount = 0;
      if (newTrades.length > 0) {
        const createRequests = newTrades.map(trade => ({
          userUid: trade.userUid, symbol: trade.symbol, type: trade.type as any,
          quantity: trade.quantity, price: trade.price, fees: trade.fees,
          timestamp: trade.timestamp, exchange: credentials.exchange,
          exchangeTradeId: trade.exchangeTradeId,
        }));

        const insertedTrades = await this.tradeRepo.batchCreateTrades(createRequests);
        syncedCount = insertedTrades.length;
      }

      // Note: IBKR backfill is handled by enclave-worker.updateSnapshotsForExchanges()

      await this.syncStatusRepo.upsertSyncStatus({
        userUid, exchange: credentials.exchange, lastSyncTime: new Date(),
        status: 'completed', totalTrades: syncedCount, errorMessage: undefined,
      });

      return syncedCount;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      await this.syncStatusRepo.upsertSyncStatus({
        userUid, exchange: credentials.exchange, lastSyncTime: new Date(),
        status: 'error', totalTrades: 0, errorMessage,
      });
      throw error;
    }
  }

  async syncTradesForStatistics(userUid: string): Promise<{ success: boolean; synced: number; message: string }> {
    try {
      const uniqueConnections = (await this.exchangeConnectionRepo.getUniqueCredentialsForUser(userUid)) ?? [];
      if (uniqueConnections.length === 0) {
        return { success: false, synced: 0, message: 'No active exchange connections found for user' };
      }

      const totalConnections = (await this.exchangeConnectionRepo.getConnectionsByUser(userUid, true)) ?? [];
      const skippedDuplicates = totalConnections.length - uniqueConnections.length;

      const syncResults = await Promise.allSettled(
        uniqueConnections.map(connection =>
          this.syncExchangeTrades(userUid, connection.id).catch(error => {
            logger.error(`Failed to sync trades from ${connection.exchange} (${connection.label})`, error);
            return 0;
          })
        )
      );

      const totalSynced = syncResults.reduce((sum, result) =>
        result.status === 'fulfilled' ? sum + result.value : sum, 0
      );

      return {
        success: true, // Success = no errors (regardless of trade count)
        synced: totalSynced,
        message: `Synced ${totalSynced} trades from ${uniqueConnections.length} unique exchanges (${skippedDuplicates} duplicates skipped)`,
      };
    } catch (error) {
      logger.error(`Trade context sync failed for user ${userUid}`, error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      return { success: false, synced: 0, message: `Trade context sync failed: ${errorMessage}` };
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

  async addExchangeConnection(userUid: string, exchange: string, label: string, apiKey: string, apiSecret: string, passphrase?: string): Promise<{ success: boolean; message: string; connectionId?: string }> {
    try {
      await this.ensureUser(userUid);

      const existingConnection = await this.exchangeConnectionRepo.findExistingConnection(userUid, exchange, label);
      if (existingConnection) {
        return {
          success: false,
          message: `A connection for ${exchange} with label "${label}" already exists. Please use a different label.`,
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
          message: `Invalid API credentials for ${exchange} - connection test failed. Please verify your API key, secret${needsPassphrase ? ', and passphrase' : ''}.`,
        };
      }

      const connection = await this.exchangeConnectionRepo.createConnection(testCredentials);
      await this.syncStatusRepo.upsertSyncStatus({
        userUid, exchange, lastSyncTime: undefined, status: 'pending',
        totalTrades: 0, errorMessage: undefined,
      });

      return {
        success: true,
        message: 'Exchange connection added successfully - snapshots will be created automatically',
        connectionId: connection.id,
      };
    } catch (error) {
      logger.error('Failed to add exchange connection', error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      if (errorMessage.includes('UNIQUE constraint failed')) {
        return {
          success: false,
          message: `A connection for ${exchange} with label "${label}" already exists. Please use a different label.`,
        };
      }
      return { success: false, message: `Failed to add exchange connection: ${errorMessage}` };
    }
  }
}