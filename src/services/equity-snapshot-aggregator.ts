import { injectable, inject } from 'tsyringe';
import { SnapshotDataRepository } from '../core/repositories/snapshot-data-repository';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { UserRepository } from '../core/repositories/user-repository';
import { UniversalConnectorCacheService } from '../core/services/universal-connector-cache.service';
import type { SnapshotData, IConnectorWithMarketTypes, IConnectorWithBalanceBreakdown, IConnectorWithBalance, MarketBalanceBreakdown, BreakdownByMarket } from '../types';
import { MarketType, getFilteredMarketTypes } from '../types/snapshot-breakdown';
import { getLogger } from '../utils/secure-enclave-logger';
import { IExchangeConnector } from '../external/interfaces/IExchangeConnector';

const logger = getLogger('EquitySnapshotAggregator');

/** Pre-compiled regex patterns for market type detection (case-insensitive). */
const MARKET_TYPE_PATTERNS = {
  swap: /PERP|SWAP|:USDT|:USD|:BUSD/i,
  future: /\d{6}/,
  options: /-[CP]/i,
  optionsExclude: /-[CP]/i,
} as const;

// Types for market trade data
interface MarketTrade {
  id: string;
  timestamp: number;
  symbol: string;
  side: string;
  price: number;
  amount: number;
  cost: number;
  fee?: { cost: number; currency: string };
}

// Type for funding fee data
interface FundingFeeData {
  amount: number;
  symbol?: string;
}

// Extended connector with optional methods
interface ExtendedConnector extends IExchangeConnector {
  getExecutedOrders?(marketType: string, since: Date): Promise<MarketTrade[]>;
  getFundingFees?(symbols: string[], since: Date): Promise<FundingFeeData[]>;
  getHistoricalSummaries?(since: Date): Promise<Array<{ date: string; breakdown: BreakdownByMarket }>>;
  getEarnBalance?(): Promise<{ equity: number; available_margin?: number }>;
}

const hasMarketTypes = (connector: unknown): connector is IConnectorWithMarketTypes => typeof (connector as IConnectorWithMarketTypes).detectMarketTypes === 'function';
const hasBalanceBreakdown = (connector: unknown): connector is IConnectorWithBalanceBreakdown => typeof (connector as IConnectorWithBalanceBreakdown).getBalanceBreakdown === 'function';
const hasGetBalance = (connector: unknown): connector is IConnectorWithBalance => typeof (connector as IConnectorWithBalance).getBalance === 'function';
const hasEarnBalance = (connector: unknown): connector is ExtendedConnector => typeof (connector as ExtendedConnector).getEarnBalance === 'function';

function roundToInterval(date: Date, intervalMinutes: number = 60): Date {
  const rounded = new Date(date);
  if (intervalMinutes >= 1440) { rounded.setUTCHours(0, 0, 0, 0); return rounded; }
  const minutes = rounded.getMinutes();
  rounded.setMinutes(Math.floor(minutes / intervalMinutes) * intervalMinutes, 0, 0);
  return rounded;
}

@injectable()
export class EquitySnapshotAggregator {
  constructor(
    @inject(SnapshotDataRepository) private readonly snapshotDataRepo: SnapshotDataRepository,
    @inject(ExchangeConnectionRepository) private readonly connectionRepo: ExchangeConnectionRepository,
    @inject(UserRepository) private readonly userRepo: UserRepository,
    @inject(UniversalConnectorCacheService) private readonly connectorCache: UniversalConnectorCacheService,
  ) {}
  // SECURITY: No TradeRepository - trades are fetched from API and aggregated in memory only

  /** Determines market type for a symbol using pre-compiled regex (O(1) per symbol). */
  private detectMarketTypeForSymbol(symbol: string): MarketType {
    if (MARKET_TYPE_PATTERNS.options.test(symbol)) {
      return 'options';
    }
    if (MARKET_TYPE_PATTERNS.swap.test(symbol)) {
      return 'swap';
    }
    if (MARKET_TYPE_PATTERNS.future.test(symbol)) {
      return 'future';
    }
    return 'spot';
  }

  /** Classifies trades by market type in single O(n) pass. */
  private classifyTradesByMarket(trades: MarketTrade[]): Record<MarketType, MarketTrade[]> {
    const classified: Record<MarketType, MarketTrade[]> = {
      spot: [],
      swap: [],
      future: [],
      options: [],
      margin: [],
      earn: [],
    };

    for (const trade of trades) {
      const marketType = this.detectMarketTypeForSymbol(trade.symbol);
      classified[marketType].push(trade);
    }

    return classified;
  }

  async updateCurrentSnapshot(userUid: string, exchange: string, label: string = ''): Promise<void> {
    const snapshot = await this.buildSnapshot(userUid, exchange, label);
    if (!snapshot) {
      return;
    }
    await this.snapshotDataRepo.upsertSnapshotData(snapshot);
    logger.info(`Updated snapshot for ${userUid} on ${exchange}/${label}: equity=${snapshot.totalEquity.toFixed(2)}, realized=${snapshot.realizedBalance.toFixed(2)}, unrealized=${snapshot.unrealizedPnL.toFixed(2)}`);
  }

  /** Build snapshot in memory (no DB save). For atomic multi-exchange sync. */
  async buildSnapshot(userUid: string, exchange: string, label: string = ''): Promise<SnapshotData | null> {
    try {
      const { connector, currentSnapshot } = await this.getConnectorAndSnapshotTime(
        userUid,
        exchange,
        label
      );
      if (!connector) {
        logger.warn(`No connector found for ${userUid}/${exchange}`);
        return null;
      }

      const { balancesByMarket, globalEquity: rawEquity, globalMargin, globalMarginUsed, filteredTypes } =
        await this.fetchBalancesByMarket(connector, exchange);

      // Ensure globalEquity is always a valid number (protection against NaN/undefined from API)
      const globalEquity = Number(rawEquity) || 0;
      if (rawEquity !== globalEquity) {
        logger.warn(`Invalid equity value for ${userUid}/${exchange}: received ${rawEquity}, using ${globalEquity}`);
      }

      // Trades window: 24h before snapshot (not start of snapshot day)
      // At 00:00 UTC, startOfDay would be the same as snapshot time → 0 trades captured.
      // Instead, always look back 24h to capture the full day's trading activity.
      const tradesSince = new Date(currentSnapshot.getTime() - 24 * 60 * 60 * 1000);
      const { tradesByMarket, swapSymbols } = await this.fetchTradesByMarket(
        exchange,
        tradesSince,
        filteredTypes,
        connector
      );

      const totalFundingFees = await this.calculateFundingFees(connector, swapSymbols, tradesSince);
      const breakdown = this.buildMarketBreakdown(
        balancesByMarket,
        tradesByMarket,
        totalFundingFees,
        globalEquity,
        globalMargin,
        globalMarginUsed
      );

      const rawUnrealizedPnl = await this.calculateUnrealizedPnl(connector, balancesByMarket);
      const totalUnrealizedPnl = Number(rawUnrealizedPnl) || 0;
      const totalRealizedBalance = globalEquity - totalUnrealizedPnl;

      const snapshot: SnapshotData = {
        id: `${userUid}-${exchange}-${label}-${currentSnapshot.toISOString()}`,
        userUid,
        timestamp: currentSnapshot.toISOString(),
        exchange,
        label,
        totalEquity: globalEquity,
        realizedBalance: totalRealizedBalance,
        unrealizedPnL: totalUnrealizedPnl,
        deposits: 0,
        withdrawals: 0,
        breakdown_by_market: breakdown,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      logger.info(`Built snapshot for ${userUid} on ${exchange}/${label}: equity=${globalEquity.toFixed(2)}, realized=${totalRealizedBalance.toFixed(2)}, unrealized=${totalUnrealizedPnl.toFixed(2)}, markets=${Object.keys(breakdown).length - 1}`);

      return snapshot;
    } catch (error) {
      logger.error(`Failed to build snapshot for ${userUid}/${exchange}/${label}`, error);
      throw error;
    }
  }

  private async getConnectorAndSnapshotTime(userUid: string, exchange: string, label: string = '') {
    const user = await this.userRepo.getUserByUid(userUid);
    if (!user) {
      logger.error(`User ${userUid} not found`);
      return { connector: null, syncInterval: 60, currentSnapshot: new Date() };
    }

    const syncInterval = user.syncIntervalMinutes || 60;
    const currentSnapshot = roundToInterval(new Date(), syncInterval);
    const connections = (await this.connectionRepo.getConnectionsByUser(userUid)) ?? [];
    const connection = connections.find(c => c.exchange === exchange && c.label === label && c.isActive);

    if (!connection) {
      logger.error(`No active connection found for ${exchange}/${label}`, {
        userUid,
        availableConnections: connections.map(c => `${c.exchange}/${c.label}`)
      });
      return { connector: null, syncInterval, currentSnapshot };
    }

    const credentials = await this.connectionRepo.getDecryptedCredentials(connection.id);
    if (!credentials) {
      logger.error(`Failed to decrypt credentials for ${exchange}`, { userUid, connectionId: connection.id });
      return { connector: null, syncInterval, currentSnapshot };
    }

    const connector = this.connectorCache.getOrCreate(exchange, credentials);
    return { connector, syncInterval, currentSnapshot };
  }

  private async fetchBalancesByMarket(connector: ExtendedConnector, exchange: string) {
    if (hasMarketTypes(connector)) {
      return this.fetchCcxtBalances(connector, exchange);
    }

    if (hasBalanceBreakdown(connector)) {
      return this.fetchBreakdownBalances(connector);
    }

    if (hasGetBalance(connector)) {
      return this.fetchBasicBalance(connector);
    }

    return { balancesByMarket: {}, globalEquity: 0, globalMargin: 0, globalMarginUsed: 0, filteredTypes: [] as MarketType[] };
  }

  private async fetchCcxtBalances(connector: ExtendedConnector & { detectMarketTypes: () => Promise<string[]>; getBalanceByMarket: (type: string) => Promise<unknown> }, exchange: string) {
    const balancesByMarket: Record<string, MarketBalanceBreakdown> = {};
    let globalEquity = 0;
    let globalMargin = 0;
    let globalMarginUsed = 0;

    const marketTypes = await connector.detectMarketTypes();
    const filteredTypes = getFilteredMarketTypes(exchange, marketTypes as MarketType[]);

    const balanceResults = await Promise.allSettled(
      filteredTypes.map(async (marketType) => ({
        marketType,
        data: await connector.getBalanceByMarket(marketType)
      }))
    );

    for (const result of balanceResults) {
      if (result.status !== 'fulfilled') continue;

      const { marketType, data } = result.value;
      const typedData = data as { equity: number; available_margin?: number; margin_used?: number };
      if (typedData.equity > 0) {
        balancesByMarket[marketType] = {
          totalEquityUsd: typedData.equity,
          unrealizedPnl: 0,
          availableBalance: typedData.available_margin,
          usedMargin: typedData.margin_used,
        };
        globalEquity += typedData.equity;
        globalMargin += typedData.available_margin || 0;
        globalMarginUsed += typedData.margin_used || 0;
      }
    }

    // Add earn balance if available
    const earnResult = await this.fetchEarnBalance(connector);
    if (earnResult) {
      balancesByMarket['earn'] = earnResult.breakdown;
      globalEquity += earnResult.equity;
    }

    return { balancesByMarket, globalEquity, globalMargin, globalMarginUsed, filteredTypes };
  }

  private async fetchEarnBalance(connector: ExtendedConnector): Promise<{ breakdown: MarketBalanceBreakdown; equity: number } | null> {
    if (!hasEarnBalance(connector)) return null;

    try {
      const earnData = await connector.getEarnBalance!();
      if (earnData.equity > 0) {
        logger.info(`Earn balance: ${earnData.equity.toFixed(2)} USD`);
        return {
          breakdown: { totalEquityUsd: earnData.equity, unrealizedPnl: 0 },
          equity: earnData.equity
        };
      }
    } catch (earnError) {
      logger.debug('Earn balance not available', { error: earnError instanceof Error ? earnError.message : String(earnError) });
    }
    return null;
  }

  private async fetchBreakdownBalances(connector: ExtendedConnector & { getBalanceBreakdown: () => Promise<Record<string, unknown>> }) {
    const balancesByMarket: Record<string, MarketBalanceBreakdown> = {};
    let globalEquity = 0;
    let globalMargin = 0;
    let globalMarginUsed = 0;

    const breakdown = await connector.getBalanceBreakdown();

    if (breakdown.global) {
      const global = breakdown.global as { equity?: number; totalEquityUsd?: number; available_margin?: number; availableBalance?: number; usedMargin?: number };
      globalEquity = global.equity || global.totalEquityUsd || 0;
      globalMargin = global.available_margin || global.availableBalance || 0;
      globalMarginUsed = global.usedMargin || 0;
    }

    for (const [marketType, marketData] of Object.entries(breakdown)) {
      const converted = this.convertBreakdownToMarketBalance(marketData);
      if (converted) {
        balancesByMarket[marketType] = converted;
      }
    }

    return { balancesByMarket, globalEquity, globalMargin, globalMarginUsed, filteredTypes: Object.keys(balancesByMarket) as MarketType[] };
  }

  private convertBreakdownToMarketBalance(marketData: unknown): MarketBalanceBreakdown | null {
    if (!marketData) return null;

    const data = marketData as {
      equity?: number; totalEquityUsd?: number; unrealizedPnl?: number; realizedPnl?: number;
      available_margin?: number; availableBalance?: number; usedMargin?: number; positions?: number;
      volume?: number; trades?: number; trading_fees?: number; tradingFees?: number;
      funding_fees?: number; fundingFees?: number;
    };

    const equityValue = data.equity ?? data.totalEquityUsd;
    if (equityValue === undefined) return null;

    return {
      totalEquityUsd: equityValue,
      unrealizedPnl: data.unrealizedPnl ?? 0,
      realizedPnl: data.realizedPnl,
      availableBalance: data.available_margin || data.availableBalance,
      usedMargin: data.usedMargin,
      positions: data.positions,
      volume: data.volume,
      trades: data.trades,
      tradingFees: data.trading_fees || data.tradingFees,
      fundingFees: data.funding_fees || data.fundingFees
    };
  }

  private async fetchBasicBalance(connector: ExtendedConnector & { getBalance: () => Promise<unknown> }) {
    const balanceData = await connector.getBalance();
    const typedBalanceData = balanceData as { equity: number; unrealizedPnl?: number; marginUsed?: number; marginAvailable?: number };

    return {
      balancesByMarket: {
        global: {
          totalEquityUsd: typedBalanceData.equity,
          unrealizedPnl: typedBalanceData.unrealizedPnl || 0,
          usedMargin: typedBalanceData.marginUsed,
          availableBalance: typedBalanceData.marginAvailable,
        }
      } as Record<string, MarketBalanceBreakdown>,
      globalEquity: typedBalanceData.equity,
      globalMargin: typedBalanceData.marginAvailable || 0,
      globalMarginUsed: typedBalanceData.marginUsed || 0,
      filteredTypes: ['global' as MarketType]
    };
  }

  /** Fetch trades in memory only (no DB). CCXT: from API, others: from historical summaries. */
  private async fetchTradesByMarket(
    exchange: string,
    since: Date,
    filteredTypes: MarketType[],
    connector: ExtendedConnector
  ) {
    const isCcxtConnector = hasMarketTypes(connector) && connector.getExecutedOrders;

    if (!isCcxtConnector) {
      // IBKR and other connectors: no individual trade storage (alpha protection)
      logger.debug(`${exchange}: Trade metrics from historical summaries only (no individual trade storage)`);
      return this.createEmptyTradesByMarket(filteredTypes);
    }

    return this.fetchCcxtTrades(exchange, since, filteredTypes, connector);
  }

  private createEmptyTradesByMarket(filteredTypes: MarketType[]) {
    const tradesByMarket: Record<string, MarketTrade[]> = {};
    for (const marketType of filteredTypes) {
      tradesByMarket[marketType] = [];
    }
    return { tradesByMarket, swapSymbols: new Set<string>() };
  }

  private async fetchCcxtTrades(
    exchange: string,
    since: Date,
    filteredTypes: MarketType[],
    connector: ExtendedConnector
  ) {
    const tradesByMarket: Record<string, MarketTrade[]> = {};
    const swapSymbols = new Set<string>();

    for (const marketType of filteredTypes) {
      const trades = await this.fetchTradesForMarketType(exchange, marketType, since, connector);
      tradesByMarket[marketType] = trades;

      if (marketType === 'swap') {
        trades.forEach((trade: MarketTrade) => swapSymbols.add(trade.symbol));
      }
    }

    return { tradesByMarket, swapSymbols };
  }

  private async fetchTradesForMarketType(
    exchange: string,
    marketType: MarketType,
    since: Date,
    connector: ExtendedConnector
  ): Promise<MarketTrade[]> {
    try {
      const trades = await connector.getExecutedOrders!(marketType, since);
      logger.debug(`Fetched ${trades.length} trades from ${exchange} ${marketType} API since ${since.toISOString()}`);
      return trades;
    } catch (apiError) {
      logger.warn(`Failed to fetch trades from ${exchange} ${marketType} API`, {
        error: apiError instanceof Error ? apiError.message : String(apiError)
      });
      return [];
    }
  }

  private async calculateFundingFees(
    connector: ExtendedConnector,
    swapSymbols: Set<string>,
    since: Date
  ): Promise<number> {
    if (swapSymbols.size === 0) {return 0;}

    try {
      const fundingData = connector.getFundingFees
        ? await connector.getFundingFees(Array.from(swapSymbols), since)
        : [];
      return fundingData.reduce((sum: number, f: FundingFeeData) => sum + f.amount, 0);
    } catch (error: unknown) {
      logger.debug('Failed to fetch funding fees, returning 0', {
        error: error instanceof Error ? error.message : String(error)
      });
      return 0;
    }
  }

  private createDualCaseMetrics(tradingFees: number, fundingFees: number) {
    return {
      tradingFees,
      trading_fees: tradingFees,
      fundingFees,
      funding_fees: fundingFees
    };
  }

  /** Calculates volume, fees, and trade count from balance or trades. */
  private calculateMarketMetrics(
    balance: MarketBalanceBreakdown | undefined,
    trades: MarketTrade[]
  ): { volume: number; fees: number; trades: number } {
    const volume = balance?.volume ?? trades.reduce((sum, t) => {
      const tradeCost = t.cost || (t.price * t.amount) || 0;
      return sum + tradeCost;
    }, 0);

    const fees = balance?.tradingFees ?? balance?.trading_fees ??
      trades.reduce((sum, t) => sum + (t.fee?.cost || 0), 0);

    const tradeCount = balance?.trades ?? trades.length;

    return { volume, fees, trades: tradeCount };
  }

  /** Builds market breakdown data structure with dual-case field names. */
  private buildMarketData(
    balance: MarketBalanceBreakdown | undefined,
    volume: number,
    trades: number,
    fees: number,
    fundingFees: number
  ): MarketBalanceBreakdown {
    return {
      totalEquityUsd: balance?.totalEquityUsd || 0,
      unrealizedPnl: balance?.unrealizedPnl || 0,
      realizedPnl: balance?.realizedPnl,
      availableBalance: balance?.availableBalance,
      usedMargin: balance?.usedMargin,
      positions: balance?.positions,
      equity: balance?.totalEquityUsd || balance?.equity || 0,
      available_margin: balance?.availableBalance || balance?.available_margin || 0,
      volume,
      trades,
      ...this.createDualCaseMetrics(fees, fundingFees)
    };
  }

  private buildMarketBreakdown(
    balancesByMarket: Record<string, MarketBalanceBreakdown>,
    tradesByMarket: Record<string, MarketTrade[]>,
    totalFundingFees: number,
    globalEquity: number,
    globalMargin: number,
    globalMarginUsed: number = 0
  ): BreakdownByMarket {
    const breakdown: BreakdownByMarket = {};

    // Collect and classify trades in single O(n) pass (optimized from O(n²) filter)
    const allTrades = Object.values(tradesByMarket).flat();
    const classifiedTrades = this.classifyTradesByMarket(allTrades);

    const standardMarkets: MarketType[] = ['spot', 'swap', 'earn', 'options'];
    let totalVolume = 0;
    let totalTrades = 0;
    let totalTradingFees = 0;

    for (const marketType of standardMarkets) {
      const marketTrades = classifiedTrades[marketType];
      const balance = balancesByMarket[marketType];

      const { volume, fees, trades } = this.calculateMarketMetrics(balance, marketTrades);
      const fundingForMarket = marketType === 'swap' ? totalFundingFees : 0;

      const marketData = this.buildMarketData(balance, volume, trades, fees, fundingForMarket);
      (breakdown as Record<string, MarketBalanceBreakdown>)[marketType] = marketData;

      totalVolume += volume;
      totalTrades += trades;
      totalTradingFees += fees;
    }

    // Process IBKR-specific market types (stocks, futures_commodities, cfd, forex)
    for (const [marketType, balance] of Object.entries(balancesByMarket)) {
      const isNonStandardMarket = marketType !== 'global' &&
        !standardMarkets.includes(marketType as MarketType);

      if (!isNonStandardMarket) {
        continue;
      }

      const volume = balance.volume || 0;
      const trades = balance.trades || 0;
      const fees = balance.tradingFees || balance.trading_fees || 0;

      const marketData = this.buildMarketData(balance, volume, trades, fees, 0);
      (breakdown as Record<string, MarketBalanceBreakdown>)[marketType] = marketData;

      totalVolume += volume;
      totalTrades += trades;
      totalTradingFees += fees;
    }

    breakdown.global = {
      totalEquityUsd: globalEquity,
      availableBalance: globalMargin,
      usedMargin: globalMarginUsed,
      unrealizedPnl: 0,
      // snake_case aliases
      equity: globalEquity,
      available_margin: globalMargin,
      // Global totals (both camelCase and snake_case)
      volume: totalVolume,
      trades: totalTrades,
      ...this.createDualCaseMetrics(totalTradingFees, totalFundingFees)
    };

    return breakdown;
  }

  private async calculateUnrealizedPnl(
    connector: ExtendedConnector,
    balancesByMarket: Record<string, MarketBalanceBreakdown>
  ): Promise<number> {
    let totalUnrealizedPnl = 0;

    try {
      const positions = await connector.getCurrentPositions();
      if (positions && Array.isArray(positions)) {
        for (const position of positions) {
          if (position.size && Number(position.size) !== 0) {
            totalUnrealizedPnl += Number(position.unrealizedPnl) || 0;
          }
        }
      }
    } catch (posError: unknown) {
      logger.debug('Failed to fetch positions, using breakdown data for unrealized PnL', {
        error: posError instanceof Error ? posError.message : String(posError)
      });
      // Fallback: use breakdown data if available
      totalUnrealizedPnl = Object.values(balancesByMarket).reduce(
        (sum, market) => sum + (market.unrealizedPnl || 0),
        0
      );
    }

    return totalUnrealizedPnl;
  }

  async backfillIbkrHistoricalSnapshots(userUid: string, exchange: string, label: string = ''): Promise<void> {
    if (exchange !== 'ibkr') {return;}
    try {
      const connections = (await this.connectionRepo.getConnectionsByUser(userUid)) ?? [];
      const connection = connections.find(c => c.exchange === exchange && c.label === label && c.isActive);
      if (!connection) {return;}
      const credentials = await this.connectionRepo.getDecryptedCredentials(connection.id);
      if (!credentials) {return;}
      const connector = this.connectorCache.getOrCreate(exchange, credentials) as ExtendedConnector;
      if (!connector.getHistoricalSummaries) {return;}
      const historicalData = await connector.getHistoricalSummaries(new Date(Date.now() - 365 * 24 * 60 * 60 * 1000));
      if (!historicalData || historicalData.length === 0) {return;}
      let processedCount = 0, skippedCount = 0;
      for (const entry of historicalData) {
        // IBKR connector uses 'equity' not 'totalEquityUsd'
        const globalEquity = entry.breakdown?.global?.equity || entry.breakdown?.global?.totalEquityUsd || 0;
        const unrealizedPnl = entry.breakdown?.global?.unrealizedPnl || 0;
        const realizedBalance = globalEquity - unrealizedPnl;

        if (globalEquity === 0) { skippedCount++; continue; }

        const year = Number.parseInt(entry.date.substring(0, 4), 10);
        const month = Number.parseInt(entry.date.substring(4, 6), 10) - 1;
        const day = Number.parseInt(entry.date.substring(6, 8), 10);

        // Create 1 daily snapshot per day in Flex report
        // IBKR Flex reports contain multiple days → we create 1 snapshot per day
        // Same output as crypto exchanges (daily snapshots), but source is different
        const snapshotDate = new Date(Date.UTC(year, month, day, 0, 0, 0, 0));

        await this.snapshotDataRepo.upsertSnapshotData({
          userUid,
          exchange,
          label,
          timestamp: snapshotDate.toISOString(),
          totalEquity: globalEquity,
          realizedBalance: realizedBalance,
          unrealizedPnL: unrealizedPnl,
          deposits: 0, // Cash flow extraction from IBKR Flex not yet implemented
          withdrawals: 0, // Cash flow extraction from IBKR Flex not yet implemented
          breakdown_by_market: entry.breakdown
        });

        processedCount++;
      }
      logger.info(`IBKR historical backfill completed for ${userUid}: ${processedCount} daily snapshots created, ${skippedCount} days skipped`);
    } catch (error) { logger.error(`Failed to backfill IBKR historical snapshots for ${userUid}`, error); throw error; }
  }
}
