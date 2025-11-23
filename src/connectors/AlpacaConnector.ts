import { RestBrokerConnector } from '../external/base/RestBrokerConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
} from '../external/interfaces/IExchangeConnector';
import { AlpacaApiService } from '../external/alpaca-api-service';
import { ExchangeCredentials } from '../types';

/**
 * Alpaca Markets Exchange Connector
 *
 * Supports:
 * - Balance fetching (Stocks + Crypto)
 * - Position tracking (current positions)
 * - Trade history (account activities)
 * - No capital flows via API (deposits/withdrawals not available)
 */
export class AlpacaConnector extends RestBrokerConnector {
  private api: AlpacaApiService;
  protected apiBaseUrl = 'https://api.alpaca.markets/v2';

  constructor(credentials: ExchangeCredentials) {
    super(credentials);

    if (!credentials.apiKey || !credentials.apiSecret) {
      throw new Error('Alpaca requires apiKey and apiSecret');
    }

    this.api = new AlpacaApiService(credentials);
  }

  getExchangeName(): string {
    return 'alpaca';
  }

  /**
   * Get authentication headers (API Key based)
   */
  protected async getAuthHeaders(): Promise<Record<string, string>> {
    return {
      'APCA-API-KEY-ID': this.credentials.apiKey!,
      'APCA-API-SECRET-KEY': this.credentials.apiSecret!,
    };
  }

  // ========================================
  // Required implementations
  // ========================================

  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      const accountInfo = await this.api.getAccountInfo();

      if (!accountInfo) {
        throw new Error('Failed to fetch Alpaca account info');
      }

      const cash = this.parseFloat(accountInfo.cash);
      const portfolioValue = this.parseFloat(accountInfo.portfolio_value);

      return this.createBalanceData(
        cash,
        portfolioValue,
        accountInfo.currency || this.defaultCurrency
      );
    });
  }

  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      const alpacaPositions = await this.api.getCurrentPositions();

      return alpacaPositions.map(pos => {
        const side = pos.side === 'long' ? 'long' : 'short';
        const size = this.parseFloat(pos.qty);

        return {
          symbol: pos.symbol,
          side: side as 'long' | 'short',
          size,
          entryPrice: this.parseFloat(pos.avg_entry_price),
          markPrice: this.parseFloat(pos.current_price),
          unrealizedPnl: this.parseFloat(pos.unrealized_pl),
          realizedPnl: 0, // Alpaca doesn't provide per-position realized PnL
          leverage: 1, // Alpaca stocks are typically 1x, margin can vary
          assetClass: pos.asset_class,
        };
      });
    });
  }

  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      // Calculate days difference
      const daysDiff = Math.ceil((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24));

      // Get trade history (FILL activities)
      const activities = await this.api.getTradeHistory(daysDiff);

      return activities
        .filter(activity => {
          const activityDate = new Date(activity.transaction_time);
          return this.isInDateRange(activityDate, startDate, endDate);
        })
        .map(activity => ({
          tradeId: activity.transaction_time, // Alpaca doesn't have trade ID in activities
          symbol: activity.symbol || '',
          side: activity.side === 'buy' ? ('buy' as const) : ('sell' as const),
          quantity: this.parseFloat(activity.qty || '0'),
          price: this.parseFloat(activity.price || '0'),
          fee: 0, // Alpaca commissions are calculated differently
          feeCurrency: this.defaultCurrency,
          timestamp: new Date(activity.transaction_time),
          orderId: '', // Not available in activity data
          realizedPnl: this.parseFloat(activity.net_amount || '0'),
        }));
    });
  }

  // ========================================
  // Alpaca-specific methods
  // ========================================
  // Note: Capital flows not supported via API (uses default implementation from BaseExchangeConnector)

  /**
   * Test connection to Alpaca
   */
  async testConnection(): Promise<boolean> {
    try {
      const isConnected = await this.api.testConnection();
      if (!isConnected) {
        this.logger.warn('Alpaca connection test failed');
      }
      return isConnected;
    } catch (error) {
      this.logger.error('Alpaca connection test error', error);
      return false;
    }
  }

  /**
   * Get portfolio history for performance tracking
   */
  async getPortfolioHistory(period: string = '1M', timeframe: string = '1D'): Promise<any> {
    try {
      return await this.api.getPortfolioHistory(period, timeframe);
    } catch (error) {
      this.handleError(error, 'getPortfolioHistory');
    }
  }
}
