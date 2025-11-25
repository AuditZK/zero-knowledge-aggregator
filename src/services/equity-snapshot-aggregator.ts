import { injectable, inject } from 'tsyringe';
import { TradeRepository } from '../core/repositories/trade-repository';
import { SnapshotDataRepository } from '../core/repositories/snapshot-data-repository';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { UserRepository } from '../core/repositories/user-repository';
import { UniversalConnectorCacheService } from '../core/services/universal-connector-cache.service';
import type { SnapshotData, IConnectorWithMarketTypes, IConnectorWithBalanceBreakdown, IConnectorWithBalance, MarketBalanceBreakdown } from '../types';
import { MarketType, getFilteredMarketTypes } from '../types/snapshot-breakdown';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('EquitySnapshotAggregator');

const hasMarketTypes = (connector: unknown): connector is IConnectorWithMarketTypes => typeof (connector as IConnectorWithMarketTypes).detectMarketTypes === 'function';
const hasBalanceBreakdown = (connector: unknown): connector is IConnectorWithBalanceBreakdown => typeof (connector as IConnectorWithBalanceBreakdown).getBalanceBreakdown === 'function';
const hasGetBalance = (connector: unknown): connector is IConnectorWithBalance => typeof (connector as IConnectorWithBalance).getBalance === 'function';

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
    @inject(TradeRepository) private readonly tradeRepo: TradeRepository,
    @inject(SnapshotDataRepository) private readonly snapshotDataRepo: SnapshotDataRepository,
    @inject(ExchangeConnectionRepository) private readonly connectionRepo: ExchangeConnectionRepository,
    @inject(UserRepository) private readonly userRepo: UserRepository,
    @inject(UniversalConnectorCacheService) private readonly connectorCache: UniversalConnectorCacheService,
  ) {}

  private matchesMarketType(symbol: string, marketType: string): boolean {
    const s = symbol.toUpperCase();
    switch (marketType) {
      case 'swap': return s.includes('PERP') || s.includes('SWAP') || s.includes(':USDT') || s.includes(':USD') || s.includes(':BUSD');
      case 'future': return /\d{6}/.test(s) && !s.includes('-C') && !s.includes('-P');
      case 'option': return s.includes('-C') || s.includes('-P');
      case 'spot':
      case 'margin': return !s.includes('PERP') && !s.includes('SWAP') && !s.includes(':USDT') && !s.includes(':USD') && !/\d{6}/.test(s) && !s.includes('-C') && !s.includes('-P');
      default: return true;
    }
  }

  async updateCurrentSnapshot(userUid: string, exchange: string): Promise<void> {
    try {
      // Step 1: Get user and connector
      const { connector, syncInterval, currentSnapshot } = await this.getConnectorAndSnapshotTime(
        userUid,
        exchange
      );
      if (!connector) {
        logger.warn(`No connector found for ${userUid}/${exchange}`);
        return;
      }

      // Step 2: Fetch balances by market type
      const { balancesByMarket, globalEquity, globalMargin, filteredTypes } =
        await this.fetchBalancesByMarket(connector, exchange);

      // Step 3: Fetch trades by market
      const since = new Date(currentSnapshot.getTime() - syncInterval * 60 * 1000);
      const { tradesByMarket, swapSymbols } = await this.fetchTradesByMarket(
        userUid,
        exchange,
        since,
        currentSnapshot,
        filteredTypes,
        connector
      );

      // Step 4: Calculate fees
      const totalFundingFees = await this.calculateFundingFees(connector, swapSymbols, since);

      // Step 5: Build market breakdown
      const breakdown = this.buildMarketBreakdown(
        balancesByMarket,
        tradesByMarket,
        totalFundingFees,
        globalEquity,
        globalMargin
      );

      // Step 6: Calculate unrealized PnL
      const totalUnrealizedPnl = await this.calculateUnrealizedPnl(connector, balancesByMarket);

      // Step 7: Save snapshot
      await this.saveSnapshot({
        userUid,
        exchange,
        currentSnapshot,
        globalEquity,
        totalUnrealizedPnl,
        breakdown
      });

      const totalRealizedBalance = globalEquity - totalUnrealizedPnl;
      logger.info(`Updated snapshot for ${userUid} on ${exchange}: equity=${globalEquity.toFixed(2)}, realized=${totalRealizedBalance.toFixed(2)}, unrealized=${totalUnrealizedPnl.toFixed(2)}, markets=${Object.keys(breakdown).length - 1}`);
    } catch (error) { logger.error(`Failed to update snapshot with breakdown for ${userUid}`, error); throw error; }
  }

  /**
   * Get connector and calculate snapshot time
   */
  private async getConnectorAndSnapshotTime(userUid: string, exchange: string) {
    const user = await this.userRepo.getUserByUid(userUid);
    if (!user) {
      logger.error(`User ${userUid} not found`);
      return { connector: null, syncInterval: 60, currentSnapshot: new Date() };
    }

    const syncInterval = user.syncIntervalMinutes || 60;
    const currentSnapshot = roundToInterval(new Date(), syncInterval);
    const connections = (await this.connectionRepo.getConnectionsByUser(userUid)) ?? [];
    const connection = connections.find(c => c.exchange === exchange && c.isActive);

    if (!connection) {
      logger.error(`No active connection found for ${exchange}`, {
        userUid,
        availableExchanges: connections.map(c => c.exchange)
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

  /**
   * Fetch balances for all market types
   */
  private async fetchBalancesByMarket(connector: any, exchange: string) {
    let balancesByMarket: Record<string, MarketBalanceBreakdown> = {};
    let globalEquity = 0;
    let globalMargin = 0;
    let filteredTypes: MarketType[] = [];

    const isCcxtConnector = hasMarketTypes(connector);

    if (isCcxtConnector) {
      const marketTypes = await connector.detectMarketTypes();
      filteredTypes = getFilteredMarketTypes(exchange, marketTypes as MarketType[]);
      const balanceResults = await Promise.allSettled(
        filteredTypes.map(async (marketType) => ({
          marketType,
          data: await connector.getBalanceByMarket(marketType)
        }))
      );

      for (const result of balanceResults) {
        if (result.status === 'fulfilled') {
          const { marketType, data } = result.value;
          const typedData = data as { equity: number; available_margin?: number };
          if (typedData.equity > 0) {
            balancesByMarket[marketType] = { totalEquityUsd: typedData.equity, unrealizedPnl: 0 };
            globalEquity += typedData.equity;
            globalMargin += typedData.available_margin || 0;
          }
        }
      }
    } else if (hasBalanceBreakdown(connector)) {
      const breakdown = await connector.getBalanceBreakdown();
      if (breakdown.global) {
        // Support both IBKR format (equity, available_margin) and standard format (totalEquityUsd, availableBalance)
        globalEquity = breakdown.global.equity || breakdown.global.totalEquityUsd || 0;
        globalMargin = breakdown.global.available_margin || breakdown.global.availableBalance || 0;
      }

      for (const [marketType, marketData] of Object.entries(breakdown)) {
        // Support both IBKR format (equity) and standard format (totalEquityUsd)
        const equityValue = marketData?.equity ?? marketData?.totalEquityUsd;
        if (marketData && equityValue !== undefined) {
          balancesByMarket[marketType] = {
            totalEquityUsd: equityValue,
            unrealizedPnl: marketData.unrealizedPnl,
            realizedPnl: marketData.realizedPnl,
            availableBalance: marketData.available_margin || marketData.availableBalance,
            usedMargin: marketData.usedMargin,
            positions: marketData.positions
          };
        }
      }
      filteredTypes = Object.keys(balancesByMarket) as MarketType[];
    } else if (hasGetBalance(connector)) {
      const balanceData = await connector.getBalance();
      const typedBalanceData = balanceData as unknown as { equity: number; unrealizedPnl?: number };
      balancesByMarket['global'] = {
        totalEquityUsd: typedBalanceData.equity,
        unrealizedPnl: typedBalanceData.unrealizedPnl || 0
      };
      globalEquity = typedBalanceData.equity;
      filteredTypes = ['global' as MarketType];
    }

    return { balancesByMarket, globalEquity, globalMargin, filteredTypes };
  }

  /**
   * Fetch trades grouped by market type
   */
  private async fetchTradesByMarket(
    userUid: string,
    exchange: string,
    since: Date,
    currentSnapshot: Date,
    filteredTypes: MarketType[],
    connector: any
  ) {
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

    const tradesByMarket: Record<string, MarketTrade[]> = {};
    const swapSymbols = new Set<string>();

    try {
      const allTrades = await this.tradeRepo.findTradesByUser(userUid, {
        exchange,
        startDate: since,
        endDate: currentSnapshot
      });

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
          fee: trade.fees ? { cost: trade.fees, currency: 'USDT' } : undefined
        }));

        if (marketType === 'swap') {
          marketTrades.forEach(trade => swapSymbols.add(trade.symbol));
        }
      }
    } catch (error) {
      // Fallback: fetch from connector API
      for (const marketType of filteredTypes) {
        try {
          const trades = (connector as any).getExecutedOrders
            ? await (connector as any).getExecutedOrders(marketType, since)
            : [];
          tradesByMarket[marketType] = trades;
          if (marketType === 'swap') {
            trades.forEach((trade: any) => swapSymbols.add(trade.symbol));
          }
        } catch (apiError) {
          tradesByMarket[marketType] = [];
        }
      }
    }

    return { tradesByMarket, swapSymbols };
  }

  /**
   * Calculate total funding fees for swap positions
   */
  private async calculateFundingFees(
    connector: any,
    swapSymbols: Set<string>,
    since: Date
  ): Promise<number> {
    if (swapSymbols.size === 0) return 0;

    try {
      const fundingData = (connector as any).getFundingFees
        ? await (connector as any).getFundingFees(Array.from(swapSymbols), since)
        : [];
      return fundingData.reduce((sum: number, f: any) => sum + f.amount, 0);
    } catch (error) {
      return 0;
    }
  }

  /**
   * Build detailed breakdown by market type
   */
  private buildMarketBreakdown(
    balancesByMarket: Record<string, MarketBalanceBreakdown>,
    tradesByMarket: Record<string, any[]>,
    totalFundingFees: number,
    globalEquity: number,
    globalMargin: number
  ) {
    const breakdown: Record<string, any> = {};
    let totalVolume = 0;
    let totalTrades = 0;
    let totalTradingFees = 0;

    for (const [marketType, trades] of Object.entries(tradesByMarket)) {
      const volume = trades.reduce((sum, t) => sum + (t.cost || 0), 0);
      const fees = trades.reduce((sum, t) => sum + (t.fee?.cost || 0), 0);
      const balance = balancesByMarket[marketType];

      const marketData: any = {
        totalEquityUsd: balance?.totalEquityUsd || 0,
        unrealizedPnl: balance?.unrealizedPnl || 0,
        realizedPnl: balance?.realizedPnl,
        availableBalance: balance?.availableBalance,
        usedMargin: balance?.usedMargin,
        positions: balance?.positions,
        volume,
        orders: trades.length,
        trading_fees: fees
      };

      if (marketType !== 'spot') {
        marketData.funding_fees = marketType === 'swap' ? totalFundingFees : 0;
      }

      breakdown[marketType] = marketData;
      totalVolume += volume;
      totalTrades += trades.length;
      totalTradingFees += fees;
    }

    breakdown['global'] = {
      totalEquityUsd: globalEquity,
      availableBalance: globalMargin,
      volume: totalVolume,
      orders: totalTrades,
      trading_fees: totalTradingFees,
      funding_fees: totalFundingFees
    };

    return breakdown;
  }

  /**
   * Calculate unrealized PnL from open positions
   */
  private async calculateUnrealizedPnl(
    connector: any,
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
      // Fallback: use breakdown data if available
      totalUnrealizedPnl = Object.values(balancesByMarket).reduce(
        (sum, market) => sum + (market.unrealizedPnl || 0),
        0
      );
    }

    return totalUnrealizedPnl;
  }

  /**
   * Save snapshot to database
   */
  private async saveSnapshot(params: {
    userUid: string;
    exchange: string;
    currentSnapshot: Date;
    globalEquity: number;
    totalUnrealizedPnl: number;
    breakdown: Record<string, any>;
  }) {
    const { userUid, exchange, currentSnapshot, globalEquity, totalUnrealizedPnl, breakdown } =
      params;

    const totalRealizedBalance = globalEquity - totalUnrealizedPnl;

    const snapshot: SnapshotData = {
      id: `${userUid}-${exchange}-${currentSnapshot.toISOString()}`,
      userUid,
      timestamp: currentSnapshot.toISOString(),
      exchange,
      totalEquity: globalEquity,
      realizedBalance: totalRealizedBalance,
      unrealizedPnL: totalUnrealizedPnl,
      deposits: 0, // TODO: Implement deposits detection from connector
      withdrawals: 0, // TODO: Implement withdrawals detection from connector
      breakdown_by_market: breakdown,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await this.snapshotDataRepo.upsertSnapshotData(snapshot);
  }

  async backfillIbkrHistoricalSnapshots(userUid: string, exchange: string): Promise<void> {
    if (exchange !== 'ibkr') return;
    try {
      const connections = (await this.connectionRepo.getConnectionsByUser(userUid)) ?? [];
      const connection = connections.find(c => c.exchange === exchange && c.isActive);
      if (!connection) return;
      const credentials = await this.connectionRepo.getDecryptedCredentials(connection.id);
      if (!credentials) return;
      const connector = this.connectorCache.getOrCreate(exchange, credentials) as any;
      if (!connector.getHistoricalSummaries) return;
      const historicalData = await connector.getHistoricalSummaries(new Date(Date.now() - 365 * 24 * 60 * 60 * 1000));
      if (!historicalData || historicalData.length === 0) return;
      let processedCount = 0, skippedCount = 0;
      for (const entry of historicalData) {
        // IBKR connector uses 'equity' not 'totalEquityUsd'
        const globalEquity = entry.breakdown?.global?.equity || entry.breakdown?.global?.totalEquityUsd || 0;
        const unrealizedPnl = entry.breakdown?.global?.unrealizedPnl || 0;
        const realizedBalance = globalEquity - unrealizedPnl;

        if (globalEquity === 0) { skippedCount++; continue; }

        const year = parseInt(entry.date.substring(0, 4));
        const month = parseInt(entry.date.substring(4, 6)) - 1;
        const day = parseInt(entry.date.substring(6, 8));

        // Create 1 daily snapshot per day in Flex report
        // IBKR Flex reports contain multiple days → we create 1 snapshot per day
        // Same output as crypto exchanges (daily snapshots), but source is different
        const snapshotDate = new Date(Date.UTC(year, month, day, 0, 0, 0, 0));

        await this.snapshotDataRepo.upsertSnapshotData({
          userUid,
          exchange,
          timestamp: snapshotDate.toISOString(),
          totalEquity: globalEquity,
          realizedBalance: realizedBalance,
          unrealizedPnL: unrealizedPnl,
          deposits: 0, // TODO: Extract deposits from IBKR Flex CashTransaction
          withdrawals: 0, // TODO: Extract withdrawals from IBKR Flex CashTransaction
          breakdown_by_market: entry.breakdown
        });

        processedCount++;
      }
      logger.info(`IBKR historical backfill completed for ${userUid}: ${processedCount} daily snapshots created, ${skippedCount} days skipped`);
    } catch (error) { logger.error(`Failed to backfill IBKR historical snapshots for ${userUid}`, error); throw error; }
  }
}
