import { injectable, inject } from 'tsyringe';
import { TradeRepository } from '../core/repositories/trade-repository';
import { SnapshotDataRepository } from '../core/repositories/snapshot-data-repository';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { UserRepository } from '../core/repositories/user-repository';
import { UniversalConnectorCacheService } from '../core/services/universal-connector-cache.service';
import type { SnapshotData, IConnectorWithMarketTypes, IConnectorWithBalanceBreakdown, IConnectorWithBalance, MarketBalanceBreakdown } from '../types';
import { MarketType, getFilteredMarketTypes } from '../types/snapshot-breakdown';
import { getLogger } from '../utils/logger.service';

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

  private async fetchBalanceForExchange(userUid: string, exchange: string): Promise<{ balance: number; equity: number }> {
    try {
      const connections = await this.connectionRepo.getConnectionsByUser(userUid);
      const connection = connections.find(c => c.exchange === exchange && c.isActive);
      if (!connection) return { balance: 0, equity: 0 };
      const credentials = await this.connectionRepo.getDecryptedCredentials(connection.id);
      if (!credentials) return { balance: 0, equity: 0 };
      const connector = this.connectorCache.getOrCreate(exchange, credentials);
      const balance = await connector.getBalance();
      let totalUnrealizedPnl = 0;
      try { const positions = await connector.getCurrentPositions(); if (positions && Array.isArray(positions)) { for (const position of positions) { if (position.size && Number(position.size) !== 0) totalUnrealizedPnl += Number(position.unrealizedPnl) || 0; } } } catch (posError: unknown) { }
      const totalEquity = balance.equity;
      const totalBalance = totalEquity - totalUnrealizedPnl;
      return { balance: totalBalance, equity: totalEquity };
    } catch (error) { logger.error(`Failed to fetch balance for ${exchange}`, error); return { balance: 0, equity: 0 }; }
  }

  private async fetchAggregateBalance(userUid: string): Promise<{ balance: number; equity: number }> {
    try {
      const connections = await this.connectionRepo.getConnectionsByUser(userUid);
      const activeConnections = connections.filter(c => c.isActive);
      let totalBalance = 0, totalEquity = 0;
      for (const connection of activeConnections) {
        try {
          const credentials = await this.connectionRepo.getDecryptedCredentials(connection.id);
          if (!credentials) continue;
          const connector = this.connectorCache.getOrCreate(connection.exchange, credentials);
          const balance = await connector.getBalance();
          totalBalance += balance.balance;
          totalEquity += balance.equity;
        } catch (error) { }
      }
      return { balance: totalBalance, equity: totalEquity };
    } catch (error) { logger.error('Failed to fetch aggregate balance', error); return { balance: 0, equity: 0 }; }
  }

  async updateCurrentSnapshot(userUid: string, exchange: string): Promise<void> {
    try {
      const user = await this.userRepo.getUserByUid(userUid);
      if (!user) { logger.error(`User ${userUid} not found`); return; }
      const syncInterval = user.syncIntervalMinutes || 60;
      const currentSnapshot = roundToInterval(new Date(), syncInterval);
      const connections = await this.connectionRepo.getConnectionsByUser(userUid);
      const connection = connections.find(c => c.exchange === exchange && c.isActive);
      if (!connection) return;
      const credentials = await this.connectionRepo.getDecryptedCredentials(connection.id);
      if (!credentials) return;
      const connector = this.connectorCache.getOrCreate(exchange, credentials);
      const isCcxtConnector = hasMarketTypes(connector);
      let balancesByMarket: Record<string, MarketBalanceBreakdown> = {};
      let globalEquity = 0;
      let globalMargin = 0;
      let filteredTypes: MarketType[] = [];
      if (isCcxtConnector) {
        const marketTypes = await connector.detectMarketTypes();
        filteredTypes = getFilteredMarketTypes(exchange, marketTypes as MarketType[]);
        const balanceResults = await Promise.allSettled(filteredTypes.map(async (marketType) => ({ marketType, data: await connector.getBalanceByMarket(marketType) })));
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
        if (breakdown.global) { globalEquity = breakdown.global.totalEquityUsd || 0; globalMargin = breakdown.global.availableBalance || 0; }
        for (const [marketType, marketData] of Object.entries(breakdown)) {
          if (marketData && marketData.totalEquityUsd !== undefined) {
            balancesByMarket[marketType] = { totalEquityUsd: marketData.totalEquityUsd, unrealizedPnl: marketData.unrealizedPnl, realizedPnl: marketData.realizedPnl, availableBalance: marketData.availableBalance, usedMargin: marketData.usedMargin, positions: marketData.positions };
          }
        }
        filteredTypes = Object.keys(balancesByMarket) as MarketType[];
      } else if (hasGetBalance(connector)) {
        const balanceData = await connector.getBalance();
        balancesByMarket['global'] = { totalEquityUsd: balanceData.equity, unrealizedPnl: balanceData.unrealizedPnl || 0 };
        globalEquity = balanceData.equity;
        filteredTypes = ['global' as MarketType];
      }
      const since = new Date(currentSnapshot.getTime() - syncInterval * 60 * 1000);
      interface MarketTrade { id: string; timestamp: number; symbol: string; side: string; price: number; amount: number; cost: number; fee?: { cost: number; currency: string; }; }
      const tradesByMarket: Record<string, MarketTrade[]> = {};
      const swapSymbols = new Set<string>();
      try {
        const allTrades = await this.tradeRepo.findTradesByUser(userUid, { exchange, startDate: since, endDate: currentSnapshot });
        for (const marketType of filteredTypes) {
          const marketTrades = allTrades.filter(trade => this.matchesMarketType(trade.symbol, marketType));
          tradesByMarket[marketType] = marketTrades.map(trade => ({ id: trade.id, timestamp: trade.timestamp.getTime(), symbol: trade.symbol, side: trade.type, price: trade.price, amount: trade.quantity, cost: trade.price * trade.quantity, fee: trade.fees ? { cost: trade.fees, currency: 'USDT' } : undefined }));
          if (marketType === 'swap') marketTrades.forEach(trade => swapSymbols.add(trade.symbol));
        }
      } catch (error) {
        for (const marketType of filteredTypes) {
          try {
            const trades = (connector as any).getExecutedOrders ? await (connector as any).getExecutedOrders(marketType, since) : [];
            tradesByMarket[marketType] = trades;
            if (marketType === 'swap') trades.forEach((trade: any) => swapSymbols.add(trade.symbol));
          } catch (apiError) { tradesByMarket[marketType] = []; }
        }
      }
      let totalFundingFees = 0;
      if (swapSymbols.size > 0) {
        try { const fundingData = (connector as any).getFundingFees ? await (connector as any).getFundingFees(Array.from(swapSymbols), since) : []; totalFundingFees = fundingData.reduce((sum: number, f: any) => sum + f.amount, 0); } catch (error) { }
      }
      interface BreakdownData extends MarketBalanceBreakdown { volume: number; orders: number; trading_fees: number; funding_fees?: number; }
      const breakdown: Record<string, any> = {};
      let totalVolume = 0, totalTrades = 0, totalTradingFees = 0;
      for (const [marketType, trades] of Object.entries(tradesByMarket)) {
        const volume = trades.reduce((sum, t) => sum + (t.cost || 0), 0);
        const fees = trades.reduce((sum, t) => sum + (t.fee?.cost || 0), 0);
        const balance = balancesByMarket[marketType];
        const marketData: any = { totalEquityUsd: balance?.totalEquityUsd || 0, unrealizedPnl: balance?.unrealizedPnl || 0, realizedPnl: balance?.realizedPnl, availableBalance: balance?.availableBalance, usedMargin: balance?.usedMargin, positions: balance?.positions, volume, orders: trades.length, trading_fees: fees };
        if (marketType !== 'spot') marketData.funding_fees = marketType === 'swap' ? totalFundingFees : 0;
        breakdown[marketType] = marketData;
        totalVolume += volume;
        totalTrades += trades.length;
        totalTradingFees += fees;
      }
      breakdown['global'] = { totalEquityUsd: globalEquity, availableBalance: globalMargin, volume: totalVolume, orders: totalTrades, trading_fees: totalTradingFees, funding_fees: totalFundingFees };
      const snapshot: SnapshotData = { id: `${userUid}-${exchange}-${currentSnapshot.toISOString()}`, userUid, timestamp: currentSnapshot.toISOString(), exchange, breakdown_by_market: breakdown, createdAt: new Date(), updatedAt: new Date() };
      await this.snapshotDataRepo.upsertSnapshotData(snapshot);
      logger.info(`Updated snapshot with breakdown for ${userUid} on ${exchange}: global equity=${globalEquity.toFixed(2)}, markets=${Object.keys(breakdown).length - 1}`);
    } catch (error) { logger.error(`Failed to update snapshot with breakdown for ${userUid}`, error); throw error; }
  }

  async backfillIbkrHistoricalSnapshots(userUid: string, exchange: string): Promise<void> {
    if (exchange !== 'ibkr') return;
    try {
      const connections = await this.connectionRepo.getConnectionsByUser(userUid);
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
        const globalEquity = entry.breakdown?.global?.totalEquityUsd || 0;
        if (globalEquity === 0) { skippedCount++; continue; }
        const year = parseInt(entry.date.substring(0, 4));
        const month = parseInt(entry.date.substring(4, 6)) - 1;
        const day = parseInt(entry.date.substring(6, 8));
        for (let hour = 0; hour < 24; hour++) {
          const snapshotDate = new Date(Date.UTC(year, month, day, hour, 0, 0, 0));
          let breakdownForHour = entry.breakdown;
          if (hour !== 0) {
            breakdownForHour = JSON.parse(JSON.stringify(entry.breakdown));
            for (const market of Object.keys(breakdownForHour)) {
              if (breakdownForHour[market]) {
                breakdownForHour[market].volume = 0;
                breakdownForHour[market].orders = 0;
                breakdownForHour[market].trading_fees = 0;
              }
            }
          }
          await this.snapshotDataRepo.upsertSnapshotData({ userUid, exchange, timestamp: snapshotDate.toISOString(), breakdown_by_market: breakdownForHour });
        }
        processedCount++;
      }
      logger.info(`IBKR historical backfill completed for ${userUid}: ${processedCount} days processed (${processedCount * 24} hourly snapshots created), ${skippedCount} days skipped`);
    } catch (error) { logger.error(`Failed to backfill IBKR historical snapshots for ${userUid}`, error); throw error; }
  }
}
