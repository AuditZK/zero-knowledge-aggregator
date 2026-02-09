import { RestBrokerConnector } from '../external/base/RestBrokerConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
} from '../external/interfaces/IExchangeConnector';
import { CTraderApiService } from '../external/ctrader-api-service';
import { ExchangeCredentials } from '../types';

/**
 * cTrader Broker Connector
 *
 * Authentication: OAuth 2.0
 * - apiKey = client_id (from cTrader Open API application)
 * - apiSecret = client_secret
 * - passphrase = access_token (obtained via OAuth flow)
 *
 * Supports:
 * - Balance fetching (account equity, margin)
 * - Position tracking (forex, CFDs, indices)
 * - Trade history (deals/closed positions)
 * - Cash flows (deposits/withdrawals - broker dependent)
 *
 * API Documentation: https://help.ctrader.com/open-api/
 * Rate limits: 50 req/s (standard), 5 req/s (historical)
 */
export class CTraderConnector extends RestBrokerConnector {
  private readonly api: CTraderApiService;
  private accountId: number | null = null;
  protected readonly apiBaseUrl = 'https://openapi.ctrader.com';

  constructor(credentials: ExchangeCredentials) {
    super(credentials);

    // OAuth flow from frontend sends access_token in apiKey
    if (!credentials.apiKey) {
      throw new Error('cTrader requires apiKey (access_token from OAuth)');
    }

    this.api = new CTraderApiService(credentials);
  }

  getExchangeName(): string {
    return 'ctrader';
  }

  /**
   * Get authentication headers
   * Note: cTrader uses query params for auth, not headers
   */
  protected async getAuthHeaders(): Promise<Record<string, string>> {
    return {};
  }

  /**
   * Ensure account ID is loaded
   */
  private async ensureAccountId(): Promise<void> {
    if (this.accountId === null) {
      const accounts = await this.api.getAccounts();

      if (accounts.length === 0) {
        throw new Error('No cTrader accounts found');
      }

      // Use first live account, or first paper account
      const liveAccount = accounts.find(a => a.isLive);
      const selectedAccount = liveAccount ?? accounts[0];

      if (!selectedAccount) {
        throw new Error('No cTrader accounts available');
      }

      this.accountId = selectedAccount.ctidTraderAccountId;
      this.api.setActiveAccount(this.accountId);

      this.logger.info(`Using cTrader account: ${this.accountId} (${selectedAccount.isLive ? 'LIVE' : 'DEMO'})`);
    }
  }

  // ========================================
  // Required implementations
  // ========================================

  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      await this.ensureAccountId();

      const balanceInfo = await this.api.getAccountBalance(this.accountId!);

      return {
        balance: balanceInfo.balance,
        equity: balanceInfo.equity,
        unrealizedPnl: balanceInfo.unrealizedPnl,
        currency: balanceInfo.currency,
        marginUsed: balanceInfo.marginUsed,
        marginAvailable: balanceInfo.marginAvailable,
      };
    });
  }

  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      await this.ensureAccountId();

      const positions = await this.api.getPositions(this.accountId!);

      // Map positions with symbol resolution
      const positionDataPromises = positions.map(async pos => {
        const symbolName = await this.api.getSymbolName(pos.tradeData.symbolId, this.accountId!);
        const side: 'long' | 'short' = pos.tradeData.tradeSide === 'BUY' ? 'long' : 'short';
        const volume = pos.tradeData.volume / 100; // Convert from cents

        return {
          symbol: symbolName,
          side,
          size: volume,
          entryPrice: pos.price / 100000, // Convert from price cents (5 decimals)
          markPrice: 0, // Would need market data API for current price
          unrealizedPnl: (pos.unrealizedNetProfit || 0) / 100,
          realizedPnl: 0,
          leverage: pos.tradeData.usedMargin ? Math.round(volume / (pos.tradeData.usedMargin / 100)) : 1,
        };
      });

      return Promise.all(positionDataPromises);
    });
  }

  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      await this.ensureAccountId();

      const deals = await this.api.getDeals(
        this.accountId!,
        startDate.getTime(),
        endDate.getTime()
      );

      // Filter to filled deals and map with symbol resolution
      const filledDeals = deals.filter(deal =>
        deal.dealStatus === 'FILLED' || deal.dealStatus === 'PARTIALLY_FILLED'
      );

      const tradeDataPromises = filledDeals.map(async deal => {
        const symbolName = await this.api.getSymbolName(deal.symbolId, this.accountId!);

        // Calculate realized PnL from closePositionDetail if available
        const realizedPnl = deal.closePositionDetail
          ? (deal.closePositionDetail.grossProfit - deal.closePositionDetail.commission - deal.closePositionDetail.swap) / 100
          : 0;

        return {
          tradeId: deal.dealId.toString(),
          symbol: symbolName,
          side: deal.tradeSide === 'BUY' ? 'buy' as const : 'sell' as const,
          quantity: deal.filledVolume / 100, // Convert from cents
          price: deal.executionPrice / 100000, // Convert from price cents
          fee: deal.commission / 100,
          feeCurrency: this.defaultCurrency,
          timestamp: new Date(deal.executionTimestamp),
          orderId: deal.orderId.toString(),
          realizedPnl,
        };
      });

      return Promise.all(tradeDataPromises);
    });
  }

  // ========================================
  // cTrader-specific methods
  // ========================================

  /**
   * Test connection to cTrader
   */
  async testConnection(): Promise<boolean> {
    try {
      const isConnected = await this.api.testConnection();
      if (!isConnected) {
        this.logger.warn('cTrader connection test failed');
      }
      return isConnected;
    } catch (error) {
      this.logger.error('cTrader connection test error', error);
      return false;
    }
  }

  /**
   * Get cash deposits and withdrawals since a date
   */
  async getCashflows(since: Date): Promise<{ deposits: number; withdrawals: number }> {
    return this.withErrorHandling('getCashflows', async () => {
      await this.ensureAccountId();

      const cashflows = await this.api.getCashflows(this.accountId!, since);

      const deposits = cashflows
        .filter(cf => cf.type === 'DEPOSIT')
        .reduce((sum, cf) => sum + cf.amount / 100, 0);

      const withdrawals = cashflows
        .filter(cf => cf.type === 'WITHDRAW')
        .reduce((sum, cf) => sum + cf.amount / 100, 0);

      if (deposits === 0 && withdrawals === 0) {
        this.logger.info('cTrader cashflows: none found or not available via API');
      } else {
        this.logger.info(`cTrader cashflows since ${since.toISOString()}: +${deposits.toFixed(2)} deposits, -${withdrawals.toFixed(2)} withdrawals`);
      }

      return { deposits, withdrawals };
    });
  }

  /**
   * Get all linked trading accounts
   */
  async getAccounts(): Promise<Array<{ id: number; isLive: boolean; brokerName: string }>> {
    const accounts = await this.api.getAccounts();
    return accounts.map(a => ({
      id: a.ctidTraderAccountId,
      isLive: a.isLive,
      brokerName: a.brokerName,
    }));
  }

  /**
   * Switch active trading account
   */
  async switchAccount(accountId: number): Promise<void> {
    const accounts = await this.api.getAccounts();
    const account = accounts.find(a => a.ctidTraderAccountId === accountId);

    if (!account) {
      throw new Error(`Account ${accountId} not found`);
    }

    this.accountId = accountId;
    this.api.setActiveAccount(accountId);
    this.logger.info(`Switched to cTrader account: ${accountId}`);
  }
}
