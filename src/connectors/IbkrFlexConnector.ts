import { BaseExchangeConnector } from '../external/base/BaseExchangeConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
  ExchangeFeature,
} from '../external/interfaces/IExchangeConnector';
import { IbkrFlexService, FlexTrade, FlexAccountSummary, FlexCashTransaction } from '../external/ibkr-flex-service';
import { ExchangeCredentials } from '../types';

/** Trade metrics by asset category with guaranteed total field */
interface IbkrTradeMetrics {
  stocks: { volume: number; count: number; fees: number };
  options: { volume: number; count: number; fees: number };
  futures_commodities: { volume: number; count: number; fees: number };
  cfd: { volume: number; count: number; fees: number };
  forex: { volume: number; count: number; fees: number };
  total: { volume: number; count: number; fees: number };
  [key: string]: { volume: number; count: number; fees: number };
}

export class IbkrFlexConnector extends BaseExchangeConnector {
  private readonly flexService: IbkrFlexService;
  private readonly flexToken: string;
  private readonly queryId: string;

  /**
   * @param credentials Exchange credentials (apiKey=token, apiSecret=queryId)
   * @param flexService Shared IbkrFlexService singleton (injected via factory)
   */
  constructor(credentials: ExchangeCredentials, flexService?: IbkrFlexService) {
    super(credentials);
    if (!credentials.apiKey || !credentials.apiSecret) {
      throw new Error('IBKR Flex requires apiKey (token) and apiSecret (queryId)');
    }

    this.flexToken = credentials.apiKey;
    this.queryId = credentials.apiSecret;
    // Use injected singleton or create new instance (for backwards compatibility/testing)
    this.flexService = flexService || new IbkrFlexService();
  }

  getExchangeName(): string {
    return 'ibkr';
  }

  supportsFeature(feature: ExchangeFeature): boolean {
    const supported: ExchangeFeature[] = ['positions', 'trades', 'historical_data'];
    return supported.includes(feature);
  }

  private async fetchFlexData<T>(parser: (xmlData: string) => Promise<T>): Promise<T> {
    const xmlData = await this.flexService.getFlexDataCached(this.flexToken, this.queryId);
    return await parser(xmlData);
  }

  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      const summaries = await this.fetchFlexData(xml => this.flexService.parseAccountSummary(xml));
      if (summaries.length === 0) {throw new Error('No account data found in Flex report');}

      summaries.sort((a, b) => a.date.localeCompare(b.date));
      const latest = summaries.at(-1)!;
      const invested = latest.stockValue + latest.optionValue + latest.commodityValue;
      return {
        balance: latest.cash,
        equity: latest.netLiquidationValue,
        unrealizedPnl: latest.unrealizedPnL,
        currency: 'USD',
        marginUsed: invested > 0 ? invested : 0,
        marginAvailable: latest.cash > 0 ? latest.cash : 0,
      };
    });
  }

  async getHistoricalSummaries(): Promise<Array<{ date: string; breakdown: Record<string, { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number }> }>> {
    return this.withErrorHandling('getHistoricalSummaries', async () => {
      // FIX: Fetch XML once, then parse both data types from same response
      // This prevents rate limiting (Error 1018) from concurrent API calls
      const xmlData = await this.flexService.getFlexDataCached(this.flexToken, this.queryId);
      const [summaries, trades] = await Promise.all([
        this.flexService.parseAccountSummary(xmlData),
        this.flexService.parseTrades(xmlData)
      ]);

      if (summaries.length === 0) {return [];}

      const tradesByDate = this.groupTradesByDate(trades);
      return summaries.map(summary => ({
        date: summary.date,
        breakdown: this.mapSummaryToBreakdown(summary, tradesByDate.get(summary.date))
      }));
    });
  }

  // IBKR asset categories for trade metrics: stocks, options, futures_commodities, cfd, forex

  // Trade metrics grouped by IBKR asset category
  private groupTradesByDate(trades: FlexTrade[]): Map<string, IbkrTradeMetrics> {
    const tradesByDate = new Map<string, IbkrTradeMetrics>();

    const createEmptyMetrics = (): IbkrTradeMetrics => ({
      stocks: { volume: 0, count: 0, fees: 0 },
      options: { volume: 0, count: 0, fees: 0 },
      futures_commodities: { volume: 0, count: 0, fees: 0 }, // FUT + CMDTY merged
      cfd: { volume: 0, count: 0, fees: 0 },
      forex: { volume: 0, count: 0, fees: 0 },
      total: { volume: 0, count: 0, fees: 0 }
    });

    for (const trade of trades) {
      const date = trade.tradeDate;
      const volume = Math.abs(trade.quantity * trade.tradePrice);
      const fees = Math.abs(trade.ibCommission || 0);

      if (!tradesByDate.has(date)) {
        tradesByDate.set(date, createEmptyMetrics());
      }

      const dayMetrics = tradesByDate.get(date)!;

      // Map IBKR assetCategory to native category names
      const category = trade.assetCategory?.toUpperCase() || 'STK';
      let marketType: string;

      switch (category) {
        case 'STK': marketType = 'stocks'; break;
        case 'OPT': marketType = 'options'; break;
        case 'FUT': case 'FOP': case 'CMDTY': marketType = 'futures_commodities'; break;
        case 'CFD': marketType = 'cfd'; break;
        case 'CASH': marketType = 'forex'; break;
        default: marketType = 'stocks'; // Default to stocks
      }

      const categoryMetrics = dayMetrics[marketType];
      if (categoryMetrics) {
        categoryMetrics.volume += volume;
        categoryMetrics.count += 1;
        categoryMetrics.fees += fees;
      }
      dayMetrics.total.volume += volume;
      dayMetrics.total.count += 1;
      dayMetrics.total.fees += fees;
    }

    return tradesByDate;
  }

  private mapSummaryToBreakdown(
    summary: FlexAccountSummary,
    tradeMetrics?: Record<string, { volume: number; count: number; fees: number }>
  ): Record<string, { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number }> {
    const getMetrics = (key: string) => tradeMetrics?.[key] || { volume: 0, count: 0, fees: 0 };
    const totalMetrics = getMetrics('total');

    // Use IBKR native category names
    return {
      global: {
        equity: summary.netLiquidationValue,
        available_margin: summary.cash,
        volume: totalMetrics.volume,
        trades: totalMetrics.count,
        trading_fees: totalMetrics.fees,
        funding_fees: 0
      },
      stocks: {
        equity: summary.stockValue,
        available_margin: 0,
        volume: getMetrics('stocks').volume,
        trades: getMetrics('stocks').count,
        trading_fees: getMetrics('stocks').fees,
        funding_fees: 0
      },
      options: {
        equity: summary.optionValue,
        available_margin: 0,
        volume: getMetrics('options').volume,
        trades: getMetrics('options').count,
        trading_fees: getMetrics('options').fees,
        funding_fees: 0
      },
      futures_commodities: {
        equity: summary.commodityValue, // IBKR commodityValue includes futures
        available_margin: 0,
        volume: getMetrics('futures_commodities').volume,
        trades: getMetrics('futures_commodities').count,
        trading_fees: getMetrics('futures_commodities').fees,
        funding_fees: 0
      },
      cfd: {
        equity: 0,
        available_margin: 0,
        volume: getMetrics('cfd').volume,
        trades: getMetrics('cfd').count,
        trading_fees: getMetrics('cfd').fees,
        funding_fees: 0
      },
      forex: {
        equity: 0,
        available_margin: 0,
        volume: getMetrics('forex').volume,
        trades: getMetrics('forex').count,
        trading_fees: getMetrics('forex').fees,
        funding_fees: 0
      }
    };
  }

  async getBalanceBreakdown(): Promise<Record<string, { equity: number; available_margin: number; volume: number; trades: number; trading_fees: number; funding_fees: number }>> {
    return this.withErrorHandling('getBalanceBreakdown', async () => {
      // FIX: Fetch XML once, then parse both data types from same response
      // This prevents rate limiting (Error 1018) from concurrent API calls
      const xmlData = await this.flexService.getFlexDataCached(this.flexToken, this.queryId);
      const [summaries, trades] = await Promise.all([
        this.flexService.parseAccountSummary(xmlData),
        this.flexService.parseTrades(xmlData)
      ]);

      if (summaries.length === 0) {throw new Error('No account data found in Flex report');}

      summaries.sort((a, b) => a.date.localeCompare(b.date));
      const latest = summaries.at(-1)!;
      const tradesByDate = this.groupTradesByDate(trades);
      return this.mapSummaryToBreakdown(latest, tradesByDate.get(latest.date));
    });
  }

  /**
   * Get deposits and withdrawals since a date
   * Uses IBKR Flex CashTransactions (type: 'Deposits' / 'Withdrawals')
   * All amounts in USD (IBKR base currency)
   */
  async getCashflows(since: Date): Promise<{ deposits: number; withdrawals: number }> {
    return this.withErrorHandling('getCashflows', async () => {
      const cashTransactions = await this.fetchFlexData(xml => this.flexService.parseCashTransactions(xml));

      let deposits = 0;
      let withdrawals = 0;

      for (const tx of cashTransactions) {
        const txDate = this.parseFlexDate(tx.date);
        if (txDate < since) continue;

        const { d, w } = this.classifyCashTransaction(tx);
        deposits += d;
        withdrawals += w;
      }

      if (deposits > 0 || withdrawals > 0) {
        this.logger.info(`IBKR cashflows since ${since.toISOString()}: +${deposits.toFixed(2)} deposits, -${withdrawals.toFixed(2)} withdrawals`);
      }

      return { deposits, withdrawals };
    });
  }

  /**
   * Get deposits/withdrawals grouped by date (YYYYMMDD format)
   * Used by historical backfill to assign cashflows to each daily snapshot
   */
  async getCashflowsByDate(since: Date): Promise<Map<string, { deposits: number; withdrawals: number }>> {
    return this.withErrorHandling('getCashflowsByDate', async () => {
      const cashTransactions = await this.fetchFlexData(xml => this.flexService.parseCashTransactions(xml));
      const byDate = new Map<string, { deposits: number; withdrawals: number }>();

      for (const tx of cashTransactions) {
        const txDate = this.parseFlexDate(tx.date);
        if (txDate < since) continue;

        // Normalize date key to YYYYMMDD (same format as historicalSummaries)
        const dateKey = this.toDateKey(tx.date);
        if (!byDate.has(dateKey)) {
          byDate.set(dateKey, { deposits: 0, withdrawals: 0 });
        }

        const entry = byDate.get(dateKey)!;
        const { d, w } = this.classifyCashTransaction(tx);
        entry.deposits += d;
        entry.withdrawals += w;
      }

      return byDate;
    });
  }

  private classifyCashTransaction(tx: FlexCashTransaction): { d: number; w: number } {
    if (tx.type === 'Deposits' || (tx.type === 'Deposits/Withdrawals' && tx.amount > 0)) {
      return { d: Math.abs(tx.amount), w: 0 };
    }
    if (tx.type === 'Withdrawals' || (tx.type === 'Deposits/Withdrawals' && tx.amount < 0)) {
      return { d: 0, w: Math.abs(tx.amount) };
    }
    return { d: 0, w: 0 };
  }

  private parseFlexDate(dateStr: string): Date {
    if (dateStr.includes('-')) {
      return new Date(dateStr);
    }
    // IBKR format: YYYYMMDD or YYYYMMDD;HHMMSS
    const datePart = dateStr.split(';')[0] ?? dateStr;
    return new Date(`${datePart.substring(0, 4)}-${datePart.substring(4, 6)}-${datePart.substring(6, 8)}T00:00:00Z`);
  }

  private toDateKey(dateStr: string): string {
    if (dateStr.includes('-')) {
      return (dateStr.split('T')[0] ?? dateStr).replace(/-/g, '');
    }
    return dateStr.split(';')[0] ?? dateStr;
  }

  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      const flexPositions = await this.fetchFlexData(xml => this.flexService.parsePositions(xml));
      return flexPositions.map(pos => {
        const side: 'long' | 'short' = pos.position > 0 ? 'long' : 'short';
        return {
          symbol: pos.symbol, side, size: Math.abs(pos.position),
          entryPrice: pos.costBasisPrice, markPrice: pos.markPrice,
          unrealizedPnl: pos.fifoPnlUnrealized, realizedPnl: 0, leverage: 1,
        };
      });
    });
  }

  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      const flexTrades = await this.fetchFlexData(xml => this.flexService.parseTrades(xml));
      return flexTrades
        .filter(trade => this.isInDateRange(new Date(trade.tradeDate), startDate, endDate))
        .map(trade => ({
          tradeId: trade.tradeID, symbol: trade.symbol,
          side: trade.buySell === 'BUY' ? ('buy' as const) : ('sell' as const),
          quantity: Math.abs(trade.quantity), price: trade.tradePrice,
          fee: Math.abs(trade.ibCommission), feeCurrency: trade.ibCommissionCurrency,
          timestamp: this.parseFlexDateTime(trade.tradeDate, trade.tradeTime),
          orderId: trade.ibOrderID, realizedPnl: trade.fifoPnlRealized,
        }));
    });
  }

  async testConnection(): Promise<boolean> {
    try {
      const isValid = await this.flexService.testConnection(this.flexToken, this.queryId);
      if (!isValid) {this.logger.warn('IBKR Flex connection test failed - invalid token or query ID');}
      return isValid;
    } catch (error) {
      this.logger.error('IBKR Flex connection test error', error);
      return false;
    }
  }

  async getFullFlexReport(): Promise<string> {
    return this.withErrorHandling('getFullFlexReport', async () => {
      return await this.fetchFlexData(xml => Promise.resolve(xml));
    });
  }

  private parseFlexDateTime(dateStr: string, timeStr: string): Date {
    if (dateStr.includes('-')) {
      return new Date(`${dateStr}T${timeStr}Z`);
    } else {
      const year = dateStr.substring(0, 4);
      const month = dateStr.substring(4, 6);
      const day = dateStr.substring(6, 8);
      return new Date(`${year}-${month}-${day}T${timeStr}Z`);
    }
  }
}
