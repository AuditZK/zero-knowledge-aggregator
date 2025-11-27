import { BaseExchangeConnector } from '../external/base/BaseExchangeConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
  ExchangeFeature,
} from '../external/interfaces/IExchangeConnector';
import { IbkrFlexService, FlexTrade, FlexAccountSummary } from '../external/ibkr-flex-service';
import { ExchangeCredentials } from '../types';

export class IbkrFlexConnector extends BaseExchangeConnector {
  private flexService: IbkrFlexService;
  private flexToken: string;
  private queryId: string;

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
      const latest = summaries[summaries.length - 1]!;
      return this.createBalanceData(latest.cash, latest.netLiquidationValue, 'USD');
    });
  }

  async getHistoricalSummaries(): Promise<Array<{ date: string; breakdown: Record<string, { equity: number; available_margin: number; volume: number; orders: number; trading_fees: number; funding_fees: number }> }>> {
    return this.withErrorHandling('getHistoricalSummaries', async () => {
      const [summaries, trades] = await Promise.all([
        this.fetchFlexData(xml => this.flexService.parseAccountSummary(xml)),
        this.fetchFlexData(xml => this.flexService.parseTrades(xml))
      ]);

      if (summaries.length === 0) {return [];}

      const tradesByDate = this.groupTradesByDate(trades);
      return summaries.map(summary => ({
        date: summary.date,
        breakdown: this.mapSummaryToBreakdown(summary, tradesByDate.get(summary.date))
      }));
    });
  }

  // IBKR asset categories for trade metrics: stocks, options, futures, cfd, forex, commodities

  // Trade metrics grouped by IBKR asset category
  private groupTradesByDate(trades: FlexTrade[]): Map<string, Record<string, { volume: number; count: number; fees: number }>> {
    const tradesByDate = new Map<string, Record<string, { volume: number; count: number; fees: number }>>();

    const createEmptyMetrics = () => ({
      stocks: { volume: 0, count: 0, fees: 0 },
      options: { volume: 0, count: 0, fees: 0 },
      futures: { volume: 0, count: 0, fees: 0 },
      cfd: { volume: 0, count: 0, fees: 0 },
      forex: { volume: 0, count: 0, fees: 0 },
      commodities: { volume: 0, count: 0, fees: 0 },
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
        case 'FUT': case 'FOP': marketType = 'futures'; break;
        case 'CFD': marketType = 'cfd'; break;
        case 'CASH': marketType = 'forex'; break;
        case 'CMDTY': marketType = 'commodities'; break;
        default: marketType = 'stocks'; // Default to stocks
      }

      const categoryMetrics = dayMetrics[marketType];
      if (categoryMetrics) {
        categoryMetrics.volume += volume;
        categoryMetrics.count += 1;
        categoryMetrics.fees += fees;
      }
      dayMetrics.total!.volume += volume;
      dayMetrics.total!.count += 1;
      dayMetrics.total!.fees += fees;
    }

    return tradesByDate;
  }

  private mapSummaryToBreakdown(
    summary: FlexAccountSummary,
    tradeMetrics?: Record<string, { volume: number; count: number; fees: number }>
  ): Record<string, { equity: number; available_margin: number; volume: number; orders: number; trading_fees: number; funding_fees: number }> {
    const getMetrics = (key: string) => tradeMetrics?.[key] || { volume: 0, count: 0, fees: 0 };
    const totalMetrics = getMetrics('total');

    // Use IBKR native category names
    return {
      global: {
        equity: summary.netLiquidationValue,
        available_margin: summary.cash,
        volume: totalMetrics.volume,
        orders: totalMetrics.count,
        trading_fees: totalMetrics.fees,
        funding_fees: 0
      },
      stocks: {
        equity: summary.stockValue,
        available_margin: 0,
        volume: getMetrics('stocks').volume,
        orders: getMetrics('stocks').count,
        trading_fees: getMetrics('stocks').fees,
        funding_fees: 0
      },
      options: {
        equity: summary.optionValue,
        available_margin: 0,
        volume: getMetrics('options').volume,
        orders: getMetrics('options').count,
        trading_fees: getMetrics('options').fees,
        funding_fees: 0
      },
      futures: {
        equity: 0, // IBKR doesn't separate futures equity in EquitySummary
        available_margin: 0,
        volume: getMetrics('futures').volume,
        orders: getMetrics('futures').count,
        trading_fees: getMetrics('futures').fees,
        funding_fees: 0
      },
      cfd: {
        equity: 0,
        available_margin: 0,
        volume: getMetrics('cfd').volume,
        orders: getMetrics('cfd').count,
        trading_fees: getMetrics('cfd').fees,
        funding_fees: 0
      },
      forex: {
        equity: 0,
        available_margin: 0,
        volume: getMetrics('forex').volume,
        orders: getMetrics('forex').count,
        trading_fees: getMetrics('forex').fees,
        funding_fees: 0
      },
      commodities: {
        equity: summary.commodityValue,
        available_margin: 0,
        volume: getMetrics('commodities').volume,
        orders: getMetrics('commodities').count,
        trading_fees: getMetrics('commodities').fees,
        funding_fees: 0
      }
    };
  }

  async getBalanceBreakdown(): Promise<Record<string, { equity: number; available_margin: number; volume: number; orders: number; trading_fees: number; funding_fees: number }>> {
    return this.withErrorHandling('getBalanceBreakdown', async () => {
      const [summaries, trades] = await Promise.all([
        this.fetchFlexData(xml => this.flexService.parseAccountSummary(xml)),
        this.fetchFlexData(xml => this.flexService.parseTrades(xml))
      ]);

      if (summaries.length === 0) {throw new Error('No account data found in Flex report');}

      summaries.sort((a, b) => a.date.localeCompare(b.date));
      const latest = summaries[summaries.length - 1]!;
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
