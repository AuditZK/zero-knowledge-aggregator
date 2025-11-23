import { injectable, inject } from 'tsyringe';
import { TradeRepository } from '../core/repositories/trade-repository';
import { SnapshotDataRepository } from '../core/repositories/snapshot-data-repository';
import { CCXTService } from '../external/ccxt-service';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { UserRepository } from '../core/repositories/user-repository';
import { UniversalConnectorCacheService } from '../core/services/universal-connector-cache.service';
import type {
  SnapshotData,
  IConnectorWithMarketTypes,
  IConnectorWithBalanceBreakdown,
  IConnectorWithBalance,
  MarketBalanceBreakdown,
  BreakdownByMarket,
} from '../types';
import type { MarketType } from '../types/snapshot-breakdown';
import { getLogger } from '../utils/logger.service';

const logger = getLogger('EquitySnapshotAggregator');

// Type guards for different connector types
function hasMarketTypes(connector: unknown): connector is IConnectorWithMarketTypes {
  return typeof (connector as IConnectorWithMarketTypes).detectMarketTypes === 'function';
}

function hasBalanceBreakdown(connector: unknown): connector is IConnectorWithBalanceBreakdown {
  return typeof (connector as IConnectorWithBalanceBreakdown).getBalanceBreakdown === 'function';
}

function hasGetBalance(connector: unknown): connector is IConnectorWithBalance {
  return typeof (connector as IConnectorWithBalance).getBalance === 'function';
}

/**
 * Round timestamp to configured sync interval
 * @param date - Date to round
 * @param intervalMinutes - Sync interval in minutes (default: 60)
 * @returns Rounded date
 *
 * Examples:
 * - interval=60: 12:37 → 12:00, 13:22 → 13:00
 * - interval=5: 12:37 → 12:35, 12:42 → 12:40
 * - interval=10: 12:37 → 12:30, 12:42 → 12:40
 * - interval=1440 (daily): any time → 00:00:00 UTC (midnight)
 */
function roundToInterval(date: Date, intervalMinutes: number = 60): Date {
  const rounded = new Date(date);

  // For daily intervals (>= 1440min = 24h), round to midnight UTC
  // This ensures daily snapshots (e.g., IBKR) are aligned on day boundaries
  if (intervalMinutes >= 1440) {
    rounded.setUTCHours(0, 0, 0, 0);
    return rounded;
  }

  // For hourly/sub-daily intervals, round to nearest hour/minute
  const minutes = rounded.getMinutes();
  const roundedMinutes = Math.floor(minutes / intervalMinutes) * intervalMinutes;
  rounded.setMinutes(roundedMinutes, 0, 0); // Set to interval boundary
  return rounded;
}

/**
 * Equity Snapshot Aggregator
 *
 * Aggregates snapshot metrics at configurable intervals (SYNC_INTERVAL_MINUTES):
 * - balance: Current account balance
 * - equity: Current account equity (balance + unrealized)
 * - volume: Trading volume in USD
 * - trades: Number of trades
 * - fees: Total trading fees
 * - fundingFee: Funding fees for perpetual contracts
 */
@injectable()
export class EquitySnapshotAggregator {
  constructor(
    @inject(TradeRepository) private readonly tradeRepo: TradeRepository,
    @inject(SnapshotDataRepository) private readonly snapshotDataRepo: SnapshotDataRepository,
    @inject(CCXTService) private readonly ccxtService: CCXTService,
    @inject(ExchangeConnectionRepository) private readonly connectionRepo: ExchangeConnectionRepository,
    @inject(UserRepository) private readonly userRepo: UserRepository,
    @inject(UniversalConnectorCacheService) private readonly connectorCache: UniversalConnectorCacheService,
  ) {}

  /**
   * Determine market type from symbol using heuristics
   *
   * Symbol patterns:
   * - Swap/Perpetual: BTC/USDT:USDT, BTC-PERP, BTCUSDT-SWAP
   * - Future: BTC-230630, BTCUSD-231231
   * - Spot: BTC/USDT, BTCUSDT, ETH/USD
   * - Margin: Same as spot (indistinguishable from symbol alone)
   * - Option: BTC-230630-40000-C, ETH-231231-3000-P
   */
  private matchesMarketType(symbol: string, marketType: string): boolean {
    const symbolUpper = symbol.toUpperCase();

    switch (marketType) {
      case 'swap':
        // Perpetual futures patterns
        return (
          symbolUpper.includes('PERP') ||
          symbolUpper.includes('SWAP') ||
          symbolUpper.includes(':USDT') ||
          symbolUpper.includes(':USD') ||
          symbolUpper.includes(':BUSD')
        );

      case 'future':
        // Dated futures (contains expiry date like 230630, 231231)
        return /\d{6}/.test(symbolUpper) && !symbolUpper.includes('-C') && !symbolUpper.includes('-P');

      case 'option':
        // Options (contains expiry, strike, and C/P flag)
        return symbolUpper.includes('-C') || symbolUpper.includes('-P');

      case 'spot':
      case 'margin':
        // Spot/Margin: anything that doesn't match above patterns
        return (
          !symbolUpper.includes('PERP') &&
          !symbolUpper.includes('SWAP') &&
          !symbolUpper.includes(':USDT') &&
          !symbolUpper.includes(':USD') &&
          !/\d{6}/.test(symbolUpper) &&
          !symbolUpper.includes('-C') &&
          !symbolUpper.includes('-P')
        );

      default:
        // Unknown market type: include all trades
        return true;
    }
  }

  /**
   * Fetch balance and equity for a specific exchange
   */
  private async fetchBalanceForExchange(
    userUid: string,
    exchange: string,
  ): Promise<{ balance: number; equity: number }> {
    try {
      // Get active connection for this exchange
      const connections = await this.connectionRepo.getConnectionsByUser(userUid);
      const connection = connections.find(c => c.exchange === exchange && c.isActive);

      if (!connection) {
        logger.warn(`No active connection found for ${userUid} on ${exchange}`);
        return { balance: 0, equity: 0 };
      }

      // Get DECRYPTED credentials
      const decryptedCredentials = await this.connectionRepo.getDecryptedCredentials(connection.id);

      if (!decryptedCredentials) {
        logger.error(`Failed to decrypt credentials for connection ${connection.id}`);
        return { balance: 0, equity: 0 };
      }

      // Create exchange instance and fetch balance
      const exchangeInstance = await this.ccxtService.createExchangeInstance({
        userUid: decryptedCredentials.userUid,
        exchange: decryptedCredentials.exchange,
        label: decryptedCredentials.label,
        apiKey: decryptedCredentials.apiKey,
        apiSecret: decryptedCredentials.apiSecret,
        passphrase: decryptedCredentials.passphrase,
      });

      if (!exchangeInstance) {
        logger.warn(`Failed to create exchange instance for ${exchange}`);
        return { balance: 0, equity: 0 };
      }

      const balanceData = await exchangeInstance.fetchBalance();

      // CCXT balance structure: { 'USD': { free, used, total }, 'BTC': {...}, total: { 'USD': X, 'BTC': Y } }
      // For Bitget futures: the API returns equity (balance + unrealized) in the total field
      let totalBalance = 0;
      let totalEquity = 0;

      // Try to get USD or USDT balance (this might already be equity for futures)
      if (balanceData['USDT']?.total) {
        totalEquity = Number(balanceData['USDT'].total) || 0;
      } else if (balanceData['USD']?.total) {
        totalEquity = Number(balanceData['USD'].total) || 0;
      } else if (balanceData['USDC']?.total) {
        totalEquity = Number(balanceData['USDC'].total) || 0;
      } else {
        // Fallback: sum all stable coins
        const stableCoins = ['USD', 'USDT', 'USDC', 'BUSD', 'DAI'];
        for (const coin of stableCoins) {
          if (balanceData[coin]?.total) {
            totalEquity += Number(balanceData[coin].total) || 0;
          }
        }
      }

      // Calculate unrealized PnL from positions to get true balance
      let totalUnrealizedPnl = 0;
      try {
        // Fetch open positions (for futures/perpetuals)
        const positions = await exchangeInstance.fetchPositions();

        if (positions && Array.isArray(positions)) {
          for (const position of positions) {
            // Only count positions with non-zero size
            if (position.contracts && Number(position.contracts) !== 0) {
              const unrealizedPnl = Number(position.unrealizedPnl) || 0;
              totalUnrealizedPnl += unrealizedPnl;
              logger.debug(`Position ${position.symbol}: unrealized PnL = ${unrealizedPnl}`);
            }
          }
        }
      } catch (posError: unknown) {
        // If fetchPositions fails (e.g., spot-only exchange), balance = equity
        const errorMsg = posError instanceof Error ? posError.message : String(posError);
        logger.debug(`Could not fetch positions for ${exchange}: ${errorMsg}`);
      }

      // For futures: Balance = Equity - Unrealized PnL
      totalBalance = totalEquity - totalUnrealizedPnl;

      logger.debug(`${exchange} - Equity: ${totalEquity.toFixed(2)}, Unrealized: ${totalUnrealizedPnl.toFixed(2)}, Balance: ${totalBalance.toFixed(2)}`);

      return {
        balance: totalBalance,
        equity: totalEquity,
      };
    } catch (error) {
      logger.error(`Failed to fetch balance for ${exchange}`, error);
      return { balance: 0, equity: 0 };
    }
  }

  /**
   * Fetch aggregate balance across all exchanges
   */
  private async fetchAggregateBalance(userUid: string): Promise<{ balance: number; equity: number }> {
    try {
      const connections = await this.connectionRepo.getConnectionsByUser(userUid);
      const activeConnections = connections.filter(c => c.isActive);

      let totalBalance = 0;
      let totalEquity = 0;

      for (const connection of activeConnections) {
        try {
          const exchangeInstance = await this.ccxtService.createExchangeInstance({
            userUid: connection.userUid,
            exchange: connection.exchange,
            label: connection.label,
            apiKey: connection.encryptedApiKey,
            apiSecret: connection.encryptedApiSecret,
            passphrase: connection.encryptedPassphrase || undefined,
          });

          if (!exchangeInstance) {
            logger.warn(`Failed to create exchange instance for ${connection.exchange}`);
            continue;
          }

          const balanceData = await exchangeInstance.fetchBalance();

          // Sum USD/USDT equivalent values
          let connectionBalance = 0;
          const stableCoins = ['USD', 'USDT', 'USDC', 'BUSD', 'DAI'];
          for (const coin of stableCoins) {
            if (balanceData[coin]?.total) {
              connectionBalance += Number(balanceData[coin].total) || 0;
            }
          }

          totalBalance += connectionBalance;
          totalEquity += connectionBalance;
        } catch (error) {
          logger.warn(`Failed to fetch balance for ${connection.exchange}`, error);
          // Continue with other exchanges
        }
      }

      return { balance: totalBalance, equity: totalEquity };
    } catch (error) {
      logger.error('Failed to fetch aggregate balance', error);
      return { balance: 0, equity: 0 };
    }
  }

  /**
   * Update snapshot with market breakdown structure
   *
   * Creates snapshots with breakdown by market type (spot, swap, global, etc.)
   *
   * @param userUid - User ID
   * @param exchange - Exchange name
   */
  async updateCurrentSnapshot(
    userUid: string,
    exchange: string
  ): Promise<void> {
    try {
      // Import types here to avoid circular dependency
      const {
        isUnifiedAccountExchange,
        getFilteredMarketTypes,
      } = await import('../../types/snapshot-breakdown');

      // Get user-specific sync interval
      const user = await this.userRepo.getUserByUid(userUid);
      if (!user) {
        logger.error(`User ${userUid} not found`);
        return;
      }

      const syncInterval = user.syncIntervalMinutes || 60;
      const currentSnapshot = roundToInterval(new Date(), syncInterval);

      // Get connection for this exchange
      const connections = await this.connectionRepo.getConnectionsByUser(userUid);
      const connection = connections.find(c => c.exchange === exchange && c.isActive);

      if (!connection) {
        logger.warn(`No active connection found for ${userUid} on ${exchange}`);
        return;
      }

      // Get decrypted credentials
      const credentials = await this.connectionRepo.getDecryptedCredentials(connection.id);
      if (!credentials) {
        logger.error(`Failed to decrypt credentials for connection ${connection.id}`);
        return;
      }

      // Get connector instance from Universal Cache (CCXT or custom brokers)
      // OPTIMIZATION: Reuses connector instances to avoid redundant initialization
      // Saves ~200ms per snapshot + reduces memory allocation
      const connector = this.connectorCache.getOrCreate(exchange, credentials);

      // 1. Detect if connector supports CCXT-style market detection
      // CCXT connectors have detectMarketTypes() and getBalanceByMarket()
      // Custom brokers (IBKR, Alpaca) have getBalanceBreakdown()

      // Debug logging
      logger.debug(`Connector type check for ${exchange}`, {
        hasDetectMarketTypes: hasMarketTypes(connector),
        hasGetBalanceBreakdown: hasBalanceBreakdown(connector),
        hasGetBalance: hasGetBalance(connector),
        connectorConstructorName: connector.constructor?.name,
      });

      const isCcxtConnector = hasMarketTypes(connector);
      logger.debug(`isCcxtConnector = ${isCcxtConnector} for ${exchange}`);

      let balancesByMarket: Record<string, MarketBalanceBreakdown> = {};
      let globalEquity = 0;
      let globalMargin = 0;
      let filteredTypes: string[] = []; // Market types to process (CCXT) or markets from breakdown (custom brokers)

      if (isCcxtConnector) {
        // CCXT-style: Detect market types and fetch balances per market
        const marketTypes = await connector.detectMarketTypes();
        filteredTypes = getFilteredMarketTypes(exchange, marketTypes) as string[];

        logger.info(`Processing markets for ${exchange} (CCXT): ${filteredTypes.join(', ')}`);

        // Fetch balances for each market (parallel execution)
        const balanceResults = await Promise.allSettled(
          filteredTypes.map(async (marketType) => ({
            marketType,
            data: await connector.getBalanceByMarket(marketType),
          }))
        );

        // Process results
        for (const result of balanceResults) {
          if (result.status === 'fulfilled') {
            const { marketType, data } = result.value;
            const typedData = data as { equity: number; available_margin?: number };
            if (typedData.equity > 0) {
              balancesByMarket[marketType] = {
                totalEquityUsd: typedData.equity,
                unrealizedPnl: 0,
              };
              globalEquity += typedData.equity;
              globalMargin += typedData.available_margin || 0;
            }
          } else {
            logger.warn(`Failed to fetch balance for market:`, result.reason);
          }
        }
      } else if (hasBalanceBreakdown(connector)) {
        // Custom broker (IBKR, Alpaca): Use getBalanceBreakdown()
        logger.info(`Processing markets for ${exchange} (custom broker)`);

        const breakdown = await connector.getBalanceBreakdown();

        // CRITICAL: Use 'global' field for total equity (most accurate)
        // The global field contains the actual Net Liquidation Value from the broker
        if (breakdown.global) {
          globalEquity = breakdown.global.equity || 0;
          globalMargin = breakdown.global.available_margin || 0;
        }

        // Convert getBalanceBreakdown format to balancesByMarket format
        // Process both global AND specific markets (stocks, options, commodities, etc.)
        for (const [marketType, marketData] of Object.entries(breakdown)) {
          if (marketData && marketData.equity !== undefined) {
            balancesByMarket[marketType] = {
              totalEquityUsd: marketData.equity,
              unrealizedPnl: marketData.unrealizedPnl,
              realizedPnl: marketData.realizedPnl,
              availableBalance: marketData.available_margin,
              usedMargin: marketData.usedMargin,
              positions: marketData.positions,
            };
          }
        }

        logger.info(`Custom broker markets: ${Object.keys(balancesByMarket).join(', ')}`);
        logger.info(`Global equity: ${globalEquity}, Global margin: ${globalMargin}`);

        // For custom brokers, use the actual market types from the breakdown
        filteredTypes = Object.keys(balancesByMarket);
      } else if (hasGetBalance(connector)) {
        // Fallback: use simple getBalance()
        logger.warn(`Connector for ${exchange} doesn't have getBalanceBreakdown, using getBalance()`);
        const balanceData = await connector.getBalance();
        balancesByMarket['global'] = {
          totalEquityUsd: balanceData.totalEquityUsd,
          unrealizedPnl: balanceData.unrealizedPnl,
        };
        globalEquity = balanceData.totalEquityUsd;
        filteredTypes = ['global'];
      }

      // 3. Fetch executed trades for each market (last syncInterval minutes)
      // OPTIMIZATION: Use DB instead of API to avoid redundant calls
      // Previous: N API calls (1 per market type) - redundant with syncExchangeTrades
      // Now: 1 DB query - trades already synced and stored in DB
      const since = new Date(currentSnapshot.getTime() - syncInterval * 60 * 1000);

      interface MarketTrade {
        id: string;
        timestamp: number;
        symbol: string;
        side: string;
        price: number;
        amount: number;
        cost: number;
        fee?: {
          cost: number;
          currency: string;
        };
      }

      const tradesByMarket: Record<string, MarketTrade[]> = {};
      const swapSymbols = new Set<string>();

      try {
        // Fetch all trades from DB (already synced by syncExchangeTrades)
        const allTrades = await this.tradeRepo.findTradesByUser(userUid, {
          exchange,
          startDate: since,
          endDate: currentSnapshot,
        });

        // Distribute trades by market type using symbol heuristics
        for (const marketType of filteredTypes) {
          const marketTrades = allTrades.filter(trade =>
            this.matchesMarketType(trade.symbol, marketType)
          );

          tradesByMarket[marketType] = marketTrades.map(trade => ({
            id: trade.id,
            timestamp: trade.timestamp.getTime(),
            symbol: trade.symbol,
            side: trade.type,
            price: trade.price,
            amount: trade.quantity,
            cost: trade.price * trade.quantity,
            fee: trade.fees ? {
              cost: trade.fees,
              currency: 'USDT', // Approximation for crypto exchanges
            } : undefined,
          }));

          // Collect symbols for funding fee lookup (swap only)
          if (marketType === 'swap') {
            marketTrades.forEach(trade => swapSymbols.add(trade.symbol));
          }
        }

        logger.debug(
          `Loaded ${allTrades.length} trades from DB for ${exchange} (saved ${filteredTypes.length} API calls)`
        );
      } catch (error) {
        logger.error(`Failed to fetch trades from DB, falling back to API:`, error);

        // Fallback: Use API if DB query fails
        for (const marketType of filteredTypes) {
          try {
            const trades = await connector.getExecutedOrders(marketType, since);
            tradesByMarket[marketType] = trades;

            if (marketType === 'swap') {
              trades.forEach(trade => swapSymbols.add(trade.symbol));
            }
          } catch (apiError) {
            logger.warn(`Failed to fetch ${marketType} trades from API:`, apiError);
            tradesByMarket[marketType] = [];
          }
        }
      }

      // 4. Fetch funding fees for swap markets
      let totalFundingFees = 0;
      if (swapSymbols.size > 0) {
        try {
          const fundingData = await connector.getFundingFees(Array.from(swapSymbols), since);
          totalFundingFees = fundingData.reduce((sum, f) => sum + f.amount, 0);
        } catch (error) {
          logger.warn('Failed to fetch funding fees:', error);
        }
      }

      // 5. Build breakdown structure
      interface BreakdownData extends MarketBalanceBreakdown {
        volume: number;
        orders: number;
        trading_fees: number;
        funding_fees?: number;
      }

      const breakdown: Record<string, BreakdownData> = {};

      // Calculate metrics for each market
      let totalVolume = 0;
      let totalTrades = 0;
      let totalTradingFees = 0;

      for (const [marketType, trades] of Object.entries(tradesByMarket)) {
        const volume = trades.reduce((sum, t) => sum + (t.cost || 0), 0);
        const fees = trades.reduce((sum, t) => sum + (t.fee?.cost || 0), 0);
        const balance = balancesByMarket[marketType];

        const marketData: BreakdownData = {
          totalEquityUsd: balance?.totalEquityUsd || 0,
          unrealizedPnl: balance?.unrealizedPnl || 0,
          realizedPnl: balance?.realizedPnl,
          availableBalance: balance?.availableBalance,
          usedMargin: balance?.usedMargin,
          positions: balance?.positions,
          volume,
          orders: trades.length, // Note: keeping 'orders' field name for backward compatibility
          trading_fees: fees,
        };

        // Only add funding_fees for derivatives markets (swap, future, option)
        if (marketType !== 'spot') {
          marketData.funding_fees = marketType === 'swap' ? totalFundingFees : 0;
        }

        breakdown[marketType] = marketData;

        totalVolume += volume;
        totalTrades += trades.length;
        totalTradingFees += fees;
      }

      // Add global breakdown
      breakdown['global'] = {
        equity: globalEquity,
        available_margin: globalMargin,
        volume: totalVolume,
        orders: totalTrades, // Note: keeping 'orders' field name for backward compatibility
        trading_fees: totalTradingFees,
        funding_fees: totalFundingFees,
      };

      // 6. Store snapshot with breakdown
      const snapshot: SnapshotData = {
        id: `${userUid}-${exchange}-${currentSnapshot.toISOString()}`,
        userUid,
        timestamp: currentSnapshot.toISOString(),
        exchange,
        breakdown_by_market: breakdown,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      await this.snapshotDataRepo.upsertSnapshotData(snapshot);

      logger.info(
        `Updated snapshot with breakdown for ${userUid} on ${exchange}: ` +
        `global equity=${globalEquity.toFixed(2)}, markets=${Object.keys(breakdown).length - 1}`
      );

    } catch (error) {
      logger.error(`Failed to update snapshot with breakdown for ${userUid}`, error);
      throw error;
    }
  }

  /**
   * Backfill historical snapshots for IBKR
   *
   * IBKR Flex Query returns 365 days of daily summaries.
   * This method creates historical snapshots in Aggregator DB for all those days.
   *
   * Called once after first IBKR sync to populate historical data.
   * Subsequent syncs only update the current snapshot.
   *
   * @param userUid - User ID
   * @param exchange - Exchange ID (must be 'ibkr')
   */
  async backfillIbkrHistoricalSnapshots(userUid: string, exchange: string): Promise<void> {
    if (exchange !== 'ibkr') {
      logger.warn(`backfillIbkrHistoricalSnapshots called for non-IBKR exchange: ${exchange}`);
      return;
    }

    try {
      logger.info(`Starting IBKR historical backfill for ${userUid}`);

      // Get connection
      const connections = await this.connectionRepo.getConnectionsByUser(userUid);
      const connection = connections.find(c => c.exchange === exchange && c.isActive);

      if (!connection) {
        logger.warn(`No active IBKR connection found for ${userUid}`);
        return;
      }

      // Get credentials
      const credentials = await this.connectionRepo.getDecryptedCredentials(connection.id);
      if (!credentials) {
        logger.error(`Failed to decrypt IBKR credentials for ${userUid}`);
        return;
      }

      // Get connector
      const connector = this.connectorCache.getOrCreate(exchange, credentials);

      // Check if connector has getHistoricalSummaries method (IBKR-specific)
      if (typeof (connector as { getHistoricalSummaries?: unknown }).getHistoricalSummaries !== 'function') {
        logger.warn(`IBKR connector doesn't have getHistoricalSummaries method`);
        return;
      }

      // Type assertion for IBKR connector
      const ibkrConnector = connector as {
        getHistoricalSummaries(since: Date): Promise<Array<{
          timestamp: Date;
          netLiquidation: number;
        }>>;
      };

      // Get historical summaries from Flex (365 days)
      logger.info(`Fetching historical summaries from IBKR Flex...`);
      const historicalData = await ibkrConnector.getHistoricalSummaries(new Date(Date.now() - 365 * 24 * 60 * 60 * 1000));
      logger.info(`Received ${historicalData.length} historical summaries from IBKR`);

      if (historicalData.length === 0) {
        logger.warn(`No historical data returned from IBKR`);
        return;
      }

      // Create snapshots for each historical day
      let processedCount = 0;
      let skippedCount = 0;

      for (const { date, breakdown } of historicalData) {
        // Skip days with no equity data (like Python script does: "if report_date and total_value")
        const globalEquity = breakdown?.global?.equity || 0;
        if (globalEquity === 0) {
          skippedCount++;
          continue;
        }

        // Parse date (YYYYMMDD format from IBKR)
        const year = parseInt(date.substring(0, 4));
        const month = parseInt(date.substring(4, 6)) - 1; // JS months are 0-indexed
        const day = parseInt(date.substring(6, 8));

        // CRITICAL: IBKR provides DAILY data only
        // Create 24 hourly snapshots (00:00-23:00) by forward-filling the daily breakdown
        // This allows cross-exchange aggregation with hourly crypto data
        for (let hour = 0; hour < 24; hour++) {
          const snapshotDate = new Date(Date.UTC(year, month, day, hour, 0, 0, 0));

          // IMPORTANT: Trading metrics (volume, orders, fees) only in 00:00 snapshot
          // Other hours get the same equity/positions but zero trading activity
          // This prevents double-counting when dashboard aggregates hourly snapshots
          let breakdownForHour = breakdown;
          if (hour !== 0) {
            // Clone breakdown and zero out trading metrics for non-00:00 hours
            breakdownForHour = JSON.parse(JSON.stringify(breakdown));
            for (const market of Object.keys(breakdownForHour)) {
              if (breakdownForHour[market]) {
                breakdownForHour[market].volume = 0;
                breakdownForHour[market].orders = 0;
                breakdownForHour[market].trading_fees = 0;
              }
            }
          }

          // Upsert snapshot with forward-filled data
          await this.snapshotDataRepo.upsertSnapshotData({
            userUid,
            exchange,
            timestamp: snapshotDate.toISOString(),
            breakdown_by_market: breakdownForHour,
          });
        }

        processedCount++;
      }

      logger.info(
        `IBKR historical backfill completed for ${userUid}: ` +
        `${processedCount} days processed (${processedCount * 24} hourly snapshots created), ` +
        `${skippedCount} days skipped (no equity), ${historicalData.length} total days in Flex data`
      );

    } catch (error) {
      logger.error(`Failed to backfill IBKR historical snapshots for ${userUid}`, error);
      throw error;
    }
  }
}
