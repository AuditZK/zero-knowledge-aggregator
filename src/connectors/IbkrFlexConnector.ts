import { BaseExchangeConnector } from '../external/base/BaseExchangeConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
  ExchangeFeature,
} from '../external/interfaces/IExchangeConnector';
import { IbkrFlexService } from '../external/ibkr-flex-service';
import { ExchangeCredentials } from '../types';

export class IbkrFlexConnector extends BaseExchangeConnector {
  private flexService: IbkrFlexService;
  private flexToken: string;
  private queryId: string;
  private accountId?: string;

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
    this.accountId = credentials.passphrase;
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
      if (summaries.length === 0) throw new Error('No account data found in Flex report');

      summaries.sort((a, b) => a.date.localeCompare(b.date));
      const latest = summaries[summaries.length - 1];
      return this.createBalanceData(latest.cash, latest.netLiquidationValue, 'USD');
    });
  }

  async getHistoricalSummaries(): Promise<Array<{ date: string; breakdown: Record<string, any> }>> {
    return this.withErrorHandling('getHistoricalSummaries', async () => {
      const [summaries, trades] = await Promise.all([
        this.fetchFlexData(xml => this.flexService.parseAccountSummary(xml)),
        this.fetchFlexData(xml => this.flexService.parseTrades(xml))
      ]);

      if (summaries.length === 0) return [];

      const tradesByDate = this.groupTradesByDate(trades);
      return summaries.map(summary => ({
        date: summary.date,
        breakdown: this.mapSummaryToBreakdown(summary, tradesByDate.get(summary.date))
      }));
    });
  }

  private groupTradesByDate(trades: any[]): Map<string, { volume: number; count: number; fees: number }> {
    const tradesByDate = new Map<string, { volume: number; count: number; fees: number }>();

    for (const trade of trades) {
      const date = trade.tradeDate;
      const volume = Math.abs(trade.quantity * trade.tradePrice);
      const fees = Math.abs(trade.ibCommission || 0);

      if (!tradesByDate.has(date)) {
        tradesByDate.set(date, { volume: 0, count: 0, fees: 0 });
      }

      const dayMetrics = tradesByDate.get(date)!;
      dayMetrics.volume += volume;
      dayMetrics.count += 1;
      dayMetrics.fees += fees;
    }

    return tradesByDate;
  }

  private mapSummaryToBreakdown(summary: any, tradeMetrics?: { volume: number; count: number; fees: number }): Record<string, any> {
    const totalValue = summary.stockValue + summary.optionValue + summary.commodityValue;
    const totalCash = summary.cash;
    const stockCash = totalValue > 0 ? (summary.stockValue / totalValue) * totalCash : totalCash;
    const optionsCash = totalValue > 0 ? (summary.optionValue / totalValue) * totalCash : 0;
    const commoditiesCash = totalValue > 0 ? (summary.commodityValue / totalValue) * totalCash : 0;
    const volume = tradeMetrics?.volume || 0;
    const orders = tradeMetrics?.count || 0;
    const trading_fees = tradeMetrics?.fees || 0;

    return {
      global: { equity: summary.netLiquidationValue, available_margin: summary.cash, volume, orders, trading_fees, funding_fees: 0 },
      stocks: { equity: summary.stockValue, available_margin: stockCash, volume, orders, trading_fees, funding_fees: 0 },
      options: { equity: summary.optionValue, available_margin: optionsCash, volume: 0, orders: 0, trading_fees: 0, funding_fees: 0 },
      commodities: { equity: summary.commodityValue, available_margin: commoditiesCash, volume: 0, orders: 0, trading_fees: 0, funding_fees: 0 },
    };
  }

  async getBalanceBreakdown(): Promise<Record<string, any>> {
    return this.withErrorHandling('getBalanceBreakdown', async () => {
      const [summaries, trades] = await Promise.all([
        this.fetchFlexData(xml => this.flexService.parseAccountSummary(xml)),
        this.fetchFlexData(xml => this.flexService.parseTrades(xml))
      ]);

      if (summaries.length === 0) throw new Error('No account data found in Flex report');

      summaries.sort((a, b) => a.date.localeCompare(b.date));
      const latest = summaries[summaries.length - 1];
      const tradesByDate = this.groupTradesByDate(trades);
      return this.mapSummaryToBreakdown(latest, tradesByDate.get(latest.date));
    });
  }

  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      const flexPositions = await this.fetchFlexData(xml => this.flexService.parsePositions(xml));
      return flexPositions.map(pos => {
        const side = pos.position > 0 ? 'long' : 'short';
        return {
          symbol: pos.symbol, side: side as 'long' | 'short', size: Math.abs(pos.position),
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
      if (!isValid) this.logger.warn('IBKR Flex connection test failed - invalid token or query ID');
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
