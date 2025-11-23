import { BaseExchangeConnector } from '../external/base/BaseExchangeConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
  CapitalFlowData,
  ExchangeFeature,
} from '../external/interfaces/IExchangeConnector';
import { IbkrFlexService } from '../external/ibkr-flex-service';
import { ExchangeCredentials } from '../types';

/**
 * IBKR Flex Web Service Connector
 *
 * Uses IBKR Flex API for read-only historical data access
 * Perfect for trading performance tracking (track record)
 *
 * Credentials format:
 * - apiKey: Flex Token (from IBKR Account Management)
 * - apiSecret: Flex Query ID (configured in IBKR)
 * - passphrase: (optional) Account ID for display
 *
 * Features:
 * - Historical trades
 * - Closed positions
 * - Cash transactions (deposits/withdrawals)
 * - Account snapshots
 *
 * Limitations:
 * - Not real-time (T+1 data)
 * - No live trading capabilities
 * - Depends on Flex Query configuration
 */
export class IbkrFlexConnector extends BaseExchangeConnector {
  private flexService: IbkrFlexService;
  private flexToken: string;
  private queryId: string;
  private accountId?: string;

  constructor(credentials: ExchangeCredentials) {
    super(credentials);

    if (!credentials.apiKey || !credentials.apiSecret) {
      throw new Error('IBKR Flex requires apiKey (token) and apiSecret (queryId)');
    }

    this.flexToken = credentials.apiKey;
    this.queryId = credentials.apiSecret;
    this.accountId = credentials.passphrase;

    this.flexService = new IbkrFlexService();
  }

  getExchangeName(): string {
    return 'ibkr';
  }

  supportsFeature(feature: ExchangeFeature): boolean {
    const supported: ExchangeFeature[] = [
      'positions',
      'trades',
      'capital_flows',
      'historical_data',
    ];
    return supported.includes(feature);
  }

  // ========================================
  // Required implementations
  // ========================================

  /**
   * Private helper to fetch and parse Flex report data
   * Uses cached Flex XML (60s TTL) to avoid duplicate API calls
   *
   * Critical for rate limiting:
   * - Trade sync and snapshot creation happen simultaneously
   * - Both call this method within ~1 second
   * - Without cache: 2 API calls → IBKR Error 1018 (rate limit)
   * - With cache: 1 API call, second uses cached data
   *
   * @param parser - Function to parse XML data into desired format
   * @returns Parsed data from Flex report
   */
  private async fetchFlexData<T>(
    parser: (xmlData: string) => Promise<T>
  ): Promise<T> {
    // Fetch Flex data with caching (prevents duplicate API calls)
    const xmlData = await this.flexService.getFlexDataCached(
      this.flexToken,
      this.queryId
    );

    // Parse XML into desired format
    return await parser(xmlData);
  }

  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      const summaries = await this.fetchFlexData(
        xml => this.flexService.parseAccountSummary(xml)
      );

      if (summaries.length === 0) {
        throw new Error('No account data found in Flex report');
      }

      // CRITICAL: Sort by date to get the most recent snapshot (date format: YYYYMMDD)
      summaries.sort((a, b) => a.date.localeCompare(b.date));
      const latest = summaries[summaries.length - 1];

      return this.createBalanceData(
        latest.cash,
        latest.netLiquidationValue,
        'USD'
      );
    });
  }

  /**
   * Get historical account summaries from Flex report
   * Returns ALL daily summaries (typically 365 days)
   *
   * Each summary contains:
   * - date: Report date (YYYYMMDD format)
   * - netLiquidationValue: Total account value
   * - stockValue, optionValue, commodityValue: Breakdown by instrument
   * - cash, unrealizedPnL, realizedPnL: Account metrics
   *
   * Used for backfilling historical snapshots in Aggregator DB
   */
  async getHistoricalSummaries(): Promise<Array<{
    date: string;
    breakdown: Record<string, any>;
  }>> {
    return this.withErrorHandling('getHistoricalSummaries', async () => {
      // Fetch both summaries and trades from Flex XML
      const [summaries, trades] = await Promise.all([
        this.fetchFlexData(xml => this.flexService.parseAccountSummary(xml)),
        this.fetchFlexData(xml => this.flexService.parseTrades(xml))
      ]);

      if (summaries.length === 0) {
        return [];
      }

      // Group trades by date and calculate volume/fees
      const tradesByDate = this.groupTradesByDate(trades);

      // Map each summary to breakdown format with date and trade metrics
      return summaries.map(summary => ({
        date: summary.date,
        breakdown: this.mapSummaryToBreakdown(summary, tradesByDate.get(summary.date))
      }));
    });
  }

  /**
   * Get balance breakdown by market type for IBKR (latest snapshot only)
   * Maps Flex account summary to breakdown_by_market structure
   *
   * IBKR Flex provides breakdown by instrument type:
   * - stockValue: Stocks/Equities
   * - optionValue: Options contracts
   * - commodityValue: Futures & Commodities
   *
   * Returns:
   * {
   *   global: { equity, cash, available_margin, ... },
   *   stocks: { equity, available_margin, ... },
   *   options: { equity, available_margin, ... },
   *   commodities: { equity, available_margin, ... }
   * }
   */
  /**
   * Group trades by date and calculate volume, count, fees
   */
  private groupTradesByDate(trades: any[]): Map<string, { volume: number; count: number; fees: number }> {
    const tradesByDate = new Map<string, { volume: number; count: number; fees: number }>();

    for (const trade of trades) {
      const date = trade.tradeDate; // Format: YYYYMMDD
      const volume = Math.abs(trade.quantity * trade.tradePrice); // Volume = quantity × price
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

  /**
   * Map a Flex account summary to breakdown_by_market structure
   * Private helper used by both getBalanceBreakdown() and getHistoricalSummaries()
   */
  private mapSummaryToBreakdown(
    summary: any,
    tradeMetrics?: { volume: number; count: number; fees: number }
  ): Record<string, any> {
    // Calculate proportional margin allocation across market types
    const totalValue = summary.stockValue + summary.optionValue + summary.commodityValue;
    const totalCash = summary.cash;

    // Allocate cash proportionally to each market type
    const stockCash = totalValue > 0 ? (summary.stockValue / totalValue) * totalCash : totalCash;
    const optionsCash = totalValue > 0 ? (summary.optionValue / totalValue) * totalCash : 0;
    const commoditiesCash = totalValue > 0 ? (summary.commodityValue / totalValue) * totalCash : 0;

    // Use trade metrics if available, otherwise default to 0
    const volume = tradeMetrics?.volume || 0;
    const orders = tradeMetrics?.count || 0;
    const trading_fees = tradeMetrics?.fees || 0;

    return {
      global: {
        equity: summary.netLiquidationValue,
        available_margin: summary.cash,
        volume,
        orders,
        trading_fees,
        funding_fees: 0,
      },
      stocks: {
        equity: summary.stockValue,
        available_margin: stockCash,
        volume,
        orders,
        trading_fees,
        funding_fees: 0,
      },
      options: {
        equity: summary.optionValue,
        available_margin: optionsCash,
        volume: 0,
        orders: 0,
        trading_fees: 0,
        funding_fees: 0,
      },
      commodities: {
        equity: summary.commodityValue,
        available_margin: commoditiesCash,
        volume: 0,
        orders: 0,
        trading_fees: 0,
        funding_fees: 0,
      },
    };
  }

  async getBalanceBreakdown(): Promise<Record<string, any>> {
    return this.withErrorHandling('getBalanceBreakdown', async () => {
      // Fetch both summaries and trades from Flex XML
      const [summaries, trades] = await Promise.all([
        this.fetchFlexData(xml => this.flexService.parseAccountSummary(xml)),
        this.fetchFlexData(xml => this.flexService.parseTrades(xml))
      ]);

      if (summaries.length === 0) {
        throw new Error('No account data found in Flex report');
      }

      // CRITICAL: Sort by date to get the most recent snapshot (date format: YYYYMMDD)
      summaries.sort((a, b) => a.date.localeCompare(b.date));
      const latest = summaries[summaries.length - 1];
      const tradesByDate = this.groupTradesByDate(trades);

      return this.mapSummaryToBreakdown(latest, tradesByDate.get(latest.date));
    });
  }

  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      const flexPositions = await this.fetchFlexData(
        xml => this.flexService.parsePositions(xml)
      );

      return flexPositions.map(pos => {
        const side = pos.position > 0 ? 'long' : 'short';
        const size = Math.abs(pos.position);

        return {
          symbol: pos.symbol,
          side: side as 'long' | 'short',
          size,
          entryPrice: pos.costBasisPrice,
          markPrice: pos.markPrice,
          unrealizedPnl: pos.fifoPnlUnrealized,
          realizedPnl: 0, // Flex doesn't provide per-position realized PnL
          leverage: 1, // IBKR stocks typically 1x
        };
      });
    });
  }

  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      const flexTrades = await this.fetchFlexData(
        xml => this.flexService.parseTrades(xml)
      );

      return flexTrades
        .filter(trade => {
          const tradeDate = new Date(trade.tradeDate);
          return this.isInDateRange(tradeDate, startDate, endDate);
        })
        .map(trade => ({
          tradeId: trade.tradeID,
          symbol: trade.symbol,
          side: trade.buySell === 'BUY' ? ('buy' as const) : ('sell' as const),
          quantity: Math.abs(trade.quantity),
          price: trade.tradePrice,
          fee: Math.abs(trade.ibCommission),
          feeCurrency: trade.ibCommissionCurrency,
          timestamp: this.parseFlexDateTime(trade.tradeDate, trade.tradeTime),
          orderId: trade.ibOrderID,
          realizedPnl: trade.fifoPnlRealized,
        }));
    });
  }

  // ========================================
  // Capital flows implementation
  // ========================================

  protected async fetchDeposits(startDate: Date, endDate: Date): Promise<CapitalFlowData[]> {
    return this.withErrorHandling('fetchDeposits', async () => {
      const cashTransactions = await this.fetchFlexData(
        xml => this.flexService.parseCashTransactions(xml)
      );

      return cashTransactions
        .filter(tx => {
          const txDate = new Date(tx.date);
          const isDeposit = tx.type === 'Deposits' || tx.type === 'Deposits & Withdrawals' && tx.amount > 0;
          return isDeposit && this.isInDateRange(txDate, startDate, endDate);
        })
        .map(tx => ({
          type: 'deposit' as const,
          amount: Math.abs(tx.amount),
          currency: tx.currency,
          timestamp: new Date(tx.date),
          txId: `${tx.date}_${tx.type}`,
          status: 'completed' as const,
          metadata: {
            description: tx.description,
            source: 'ibkr_flex',
          },
        }));
    });
  }

  protected async fetchWithdrawals(startDate: Date, endDate: Date): Promise<CapitalFlowData[]> {
    return this.withErrorHandling('fetchWithdrawals', async () => {
      const cashTransactions = await this.fetchFlexData(
        xml => this.flexService.parseCashTransactions(xml)
      );

      return cashTransactions
        .filter(tx => {
          const txDate = new Date(tx.date);
          const isWithdrawal = tx.type === 'Withdrawals' || tx.type === 'Deposits & Withdrawals' && tx.amount < 0;
          return isWithdrawal && this.isInDateRange(txDate, startDate, endDate);
        })
        .map(tx => ({
          type: 'withdrawal' as const,
          amount: Math.abs(tx.amount),
          currency: tx.currency,
          timestamp: new Date(tx.date),
          txId: `${tx.date}_${tx.type}`,
          status: 'completed' as const,
          metadata: {
            description: tx.description,
            source: 'ibkr_flex',
          },
        }));
    });
  }

  // ========================================
  // IBKR Flex-specific methods
  // ========================================

  /**
   * Test connection by requesting a Flex report
   */
  async testConnection(): Promise<boolean> {
    try {
      const isValid = await this.flexService.testConnection(this.flexToken, this.queryId);
      if (!isValid) {
        this.logger.warn('IBKR Flex connection test failed - invalid token or query ID');
      }
      return isValid;
    } catch (error) {
      this.logger.error('IBKR Flex connection test error', error);
      return false;
    }
  }

  /**
   * Get full Flex report (for advanced users)
   */
  async getFullFlexReport(): Promise<string> {
    return this.withErrorHandling('getFullFlexReport', async () => {
      return await this.fetchFlexData(xml => Promise.resolve(xml));
    });
  }

  // ========================================
  // Private helpers
  // ========================================

  /**
   * Parse IBKR Flex date+time into JS Date
   * Format: "2025-01-15" + "09:30:00"
   */
  private parseFlexDateTime(dateStr: string, timeStr: string): Date {
    // Flex date format: "YYYYMMDD" or "YYYY-MM-DD"
    // Flex time format: "HH:MM:SS"

    if (dateStr.includes('-')) {
      // Already in ISO format
      return new Date(`${dateStr}T${timeStr}Z`);
    } else {
      // Convert YYYYMMDD to YYYY-MM-DD
      const year = dateStr.substring(0, 4);
      const month = dateStr.substring(4, 6);
      const day = dateStr.substring(6, 8);
      return new Date(`${year}-${month}-${day}T${timeStr}Z`);
    }
  }
}
