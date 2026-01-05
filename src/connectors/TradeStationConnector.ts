import { RestBrokerConnector } from '../external/base/RestBrokerConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
} from '../external/interfaces/IExchangeConnector';
import { TradeStationApiService } from '../external/tradestation-api-service';
import { ExchangeCredentials } from '../types';

/**
 * TradeStation Broker Connector
 *
 * Authentication: OAuth 2.0
 * - apiKey = client_id
 * - apiSecret = client_secret
 * - passphrase = refresh_token
 *
 * Supports:
 * - Balance fetching (all account types aggregated)
 * - Position tracking (stocks, options, futures)
 * - Trade history (historical orders)
 * - No capital flows via API (deposits/withdrawals not reliably exposed)
 */
export class TradeStationConnector extends RestBrokerConnector {
  private api: TradeStationApiService;
  private accountIds: string[] = [];
  protected apiBaseUrl = 'https://api.tradestation.com';

  constructor(credentials: ExchangeCredentials) {
    super(credentials);

    if (!credentials.apiKey || !credentials.apiSecret || !credentials.passphrase) {
      throw new Error('TradeStation requires apiKey (client_id), apiSecret (client_secret), and passphrase (refresh_token)');
    }

    this.api = new TradeStationApiService(credentials);
  }

  getExchangeName(): string {
    return 'tradestation';
  }

  /**
   * Get authentication headers (OAuth 2.0)
   * Note: Actual auth is handled by TradeStationApiService
   */
  protected async getAuthHeaders(): Promise<Record<string, string>> {
    // Auth is handled internally by the API service
    return {};
  }

  /**
   * Ensure account IDs are loaded
   */
  private async ensureAccountIds(): Promise<void> {
    if (this.accountIds.length === 0) {
      const accounts = await this.api.getAccounts();
      this.accountIds = accounts.map(a => a.AccountID);

      if (this.accountIds.length === 0) {
        throw new Error('No TradeStation accounts found');
      }

      this.logger.info(`Found ${this.accountIds.length} TradeStation account(s)`);
    }
  }

  // ========================================
  // Required implementations
  // ========================================

  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      const aggregated = await this.api.getAggregatedBalance();

      if (!aggregated) {
        throw new Error('Failed to fetch TradeStation account info');
      }

      // Cache account IDs for other methods
      this.accountIds = aggregated.accounts.map(a => a.AccountID);

      return this.createBalanceData(
        aggregated.totalCash,
        aggregated.totalEquity,
        aggregated.currency
      );
    });
  }

  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      await this.ensureAccountIds();

      const positions = await this.api.getPositions(this.accountIds);

      return positions.map(pos => ({
        symbol: pos.Symbol,
        side: pos.LongShort === 'Long' ? 'long' as const : 'short' as const,
        size: Math.abs(pos.Quantity),
        entryPrice: pos.AveragePrice,
        markPrice: pos.Last,
        unrealizedPnl: pos.UnrealizedProfitLoss,
        realizedPnl: 0, // Not available per-position
        leverage: 1, // TradeStation doesn't expose leverage per position
        assetType: pos.AssetType,
      }));
    });
  }

  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      await this.ensureAccountIds();

      const orders = await this.api.getHistoricalOrders(this.accountIds, startDate);

      // Filter to filled orders only and within date range
      const filledOrders = orders.filter(order => {
        if (order.Status !== 'Filled' && order.Status !== 'FLL') {
          return false;
        }

        const orderDate = new Date(order.ClosedDateTime || order.OpenedDateTime);
        return this.isInDateRange(orderDate, startDate, endDate);
      });

      // Convert orders to trades (handle multi-leg orders)
      const trades: TradeData[] = [];

      for (const order of filledOrders) {
        // Handle legs (for options spreads, etc.)
        for (const leg of order.Legs) {
          if (leg.ExecQuantity && leg.ExecQuantity > 0) {
            trades.push({
              tradeId: `${order.OrderID}-${leg.Symbol}`,
              symbol: leg.Symbol,
              side: leg.BuyOrSell === 'Buy' ? 'buy' as const : 'sell' as const,
              quantity: leg.ExecQuantity,
              price: leg.ExecPrice || order.FilledPrice || 0,
              fee: (order.Commission || 0) + (order.RoutingFee || 0),
              feeCurrency: this.defaultCurrency,
              timestamp: new Date(order.ClosedDateTime || order.OpenedDateTime),
              orderId: order.OrderID,
              realizedPnl: 0, // TradeStation doesn't provide per-trade PnL
            });
          }
        }

        // If no legs with execution, use order-level data
        if (order.Legs.every(l => !l.ExecQuantity) && order.FilledQuantity) {
          trades.push({
            tradeId: order.OrderID,
            symbol: order.Symbol,
            side: order.Legs[0]?.BuyOrSell === 'Buy' ? 'buy' as const : 'sell' as const,
            quantity: order.FilledQuantity,
            price: order.FilledPrice || 0,
            fee: (order.Commission || 0) + (order.RoutingFee || 0),
            feeCurrency: this.defaultCurrency,
            timestamp: new Date(order.ClosedDateTime || order.OpenedDateTime),
            orderId: order.OrderID,
            realizedPnl: 0,
          });
        }
      }

      return trades;
    });
  }

  // ========================================
  // TradeStation-specific methods
  // ========================================

  /**
   * Test connection to TradeStation
   */
  async testConnection(): Promise<boolean> {
    try {
      const isConnected = await this.api.testConnection();
      if (!isConnected) {
        this.logger.warn('TradeStation connection test failed');
      }
      return isConnected;
    } catch (error) {
      this.logger.error('TradeStation connection test error', error);
      return false;
    }
  }

  /**
   * Get cash deposits and withdrawals since a date
   * Note: TradeStation may not expose this via API
   */
  async getCashflows(since: Date): Promise<{ deposits: number; withdrawals: number }> {
    return this.withErrorHandling('getCashflows', async () => {
      await this.ensureAccountIds();

      const cashflows = await this.api.getCashflows(this.accountIds, since);

      const deposits = cashflows
        .filter(cf => cf.type === 'deposit')
        .reduce((sum, cf) => sum + cf.amount, 0);

      const withdrawals = cashflows
        .filter(cf => cf.type === 'withdrawal')
        .reduce((sum, cf) => sum + cf.amount, 0);

      if (deposits === 0 && withdrawals === 0) {
        this.logger.info('TradeStation cashflows not available via API - returning zero');
      } else {
        this.logger.info(`TradeStation cashflows since ${since.toISOString()}: +${deposits.toFixed(2)} deposits, -${withdrawals.toFixed(2)} withdrawals`);
      }

      return { deposits, withdrawals };
    });
  }

  /**
   * Get list of account IDs
   */
  async getAccountIds(): Promise<string[]> {
    await this.ensureAccountIds();
    return [...this.accountIds];
  }
}
