import { injectable } from 'tsyringe';
import type { ExchangeCredentials } from '../types';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('TradeStationApiService');

/**
 * TradeStation API v3 Service (Read-only for enclave)
 *
 * Authentication: OAuth 2.0 with refresh token
 * - apiKey = client_id
 * - apiSecret = client_secret
 * - passphrase = refresh_token
 */

// TradeStation API response types
export interface TradeStationAccount {
  AccountID: string;
  AccountType: string;
  Alias: string;
  Currency: string;
  Status: string;
  StatusDescription: string;
}

export interface TradeStationBalance {
  AccountID: string;
  AccountType: string;
  CashBalance: number;
  BuyingPower: number;
  Equity: number;
  MarketValue: number;
  TodaysProfitLoss: number;
  UnrealizedProfitLoss: number;
  RealizedProfitLoss?: number;
  UnclearedDeposit?: number;
  OptionBuyingPower?: number;
  DayTradingBuyingPower?: number;
  DayTradesRemaining?: number;
  MaintenanceRate?: number;
  Currency?: string;
}

export interface TradeStationPosition {
  AccountID: string;
  Symbol: string;
  Quantity: number;
  AveragePrice: number;
  Last: number;
  Bid: number;
  Ask: number;
  MarketValue: number;
  TodaysProfitLoss: number;
  UnrealizedProfitLoss: number;
  UnrealizedProfitLossPercent: number;
  UnrealizedProfitLossQty: number;
  LongShort: 'Long' | 'Short';
  AssetType: string;
  ConversionRate?: number;
  InitialRequirement?: number;
  MaintenanceRequirement?: number;
}

export interface TradeStationOrder {
  AccountID: string;
  OrderID: string;
  Symbol: string;
  Type: string;
  Status: string;
  StatusDescription: string;
  OpenedDateTime: string;
  ClosedDateTime?: string;
  FilledPrice?: number;
  FilledQuantity?: number;
  OrderedQuantity: number;
  LimitPrice?: number;
  StopPrice?: number;
  Duration: string;
  Legs: Array<{
    BuyOrSell: 'Buy' | 'Sell';
    Quantity: number;
    ExecPrice?: number;
    ExecQuantity?: number;
    Symbol: string;
    AssetType: string;
  }>;
  Commission?: number;
  RoutingFee?: number;
}

export interface TradeStationCashflow {
  id: string;
  type: 'deposit' | 'withdrawal';
  amount: number;
  date: Date;
  description: string;
}

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}

@injectable()
export class TradeStationApiService {
  private clientId: string;
  private clientSecret: string;
  private refreshToken: string;
  private accessToken: string | null = null;
  private tokenExpiry: number = 0;

  private readonly baseUrl = 'https://api.tradestation.com';
  private readonly authUrl = 'https://signin.tradestation.com/oauth/token';

  constructor(credentials: ExchangeCredentials) {
    if (!credentials.apiKey || !credentials.apiSecret || !credentials.passphrase) {
      throw new Error('TradeStation requires apiKey (client_id), apiSecret (client_secret), and passphrase (refresh_token)');
    }

    this.clientId = credentials.apiKey;
    this.clientSecret = credentials.apiSecret;
    this.refreshToken = credentials.passphrase;
  }

  /**
   * Get OAuth access token (refresh if expired)
   */
  private async getAccessToken(): Promise<string> {
    // Return cached token if still valid (with 60s buffer)
    if (this.accessToken && Date.now() < this.tokenExpiry - 60000) {
      return this.accessToken;
    }

    try {
      const response = await fetch(this.authUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: this.clientId,
          client_secret: this.clientSecret,
          refresh_token: this.refreshToken,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OAuth token refresh failed: ${response.status} - ${errorText}`);
      }

      const tokenData = await response.json() as TokenResponse;

      this.accessToken = tokenData.access_token;
      this.tokenExpiry = Date.now() + (tokenData.expires_in * 1000);

      // Update refresh token if a new one is provided
      if (tokenData.refresh_token) {
        this.refreshToken = tokenData.refresh_token;
      }

      logger.info('TradeStation OAuth token refreshed successfully');
      return this.accessToken;
    } catch (error) {
      logger.error('Failed to refresh TradeStation OAuth token', error);
      throw error;
    }
  }

  /**
   * Make authenticated API request
   */
  private async makeRequest<T>(endpoint: string, params?: Record<string, string>): Promise<T> {
    const token = await this.getAccessToken();

    let url = `${this.baseUrl}${endpoint}`;
    if (params) {
      const queryString = new URLSearchParams(params).toString();
      url = `${url}?${queryString}`;
    }

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`TradeStation API error: ${response.status} - ${errorText}`);
    }

    return await response.json() as T;
  }

  /**
   * Test connection to TradeStation
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.getAccounts();
      return true;
    } catch (error) {
      logger.error('TradeStation connection test failed', error);
      return false;
    }
  }

  /**
   * Get all accounts
   */
  async getAccounts(): Promise<TradeStationAccount[]> {
    try {
      const response = await this.makeRequest<{ Accounts: TradeStationAccount[] }>(
        '/v3/brokerage/accounts'
      );
      return response.Accounts || [];
    } catch (error) {
      logger.error('Failed to fetch TradeStation accounts', error);
      return [];
    }
  }

  /**
   * Get account balances
   */
  async getBalances(accountIds: string[]): Promise<TradeStationBalance[]> {
    try {
      const accountKeysParam = accountIds.join(',');
      const response = await this.makeRequest<{ Balances: TradeStationBalance[] }>(
        `/v3/brokerage/accounts/${accountKeysParam}/balances`
      );
      return response.Balances || [];
    } catch (error) {
      logger.error('Failed to fetch TradeStation balances', error);
      return [];
    }
  }

  /**
   * Get positions for accounts
   */
  async getPositions(accountIds: string[]): Promise<TradeStationPosition[]> {
    try {
      const accountKeysParam = accountIds.join(',');
      const response = await this.makeRequest<{ Positions: TradeStationPosition[] }>(
        `/v3/brokerage/accounts/${accountKeysParam}/positions`
      );
      return response.Positions || [];
    } catch (error) {
      logger.error('Failed to fetch TradeStation positions', error);
      return [];
    }
  }

  /**
   * Get historical orders (trades)
   */
  async getHistoricalOrders(accountIds: string[], since: Date): Promise<TradeStationOrder[]> {
    try {
      const accountKeysParam = accountIds.join(',');
      const response = await this.makeRequest<{ Orders: TradeStationOrder[] }>(
        `/v3/brokerage/accounts/${accountKeysParam}/historicalorders`,
        { since: since.toISOString() }
      );
      return response.Orders || [];
    } catch (error) {
      logger.error('Failed to fetch TradeStation historical orders', error);
      return [];
    }
  }

  /**
   * Get account transactions for cashflow tracking
   * Note: TradeStation may not expose deposits/withdrawals via API
   * This attempts to parse from transaction history if available
   */
  async getCashflows(accountIds: string[], since: Date): Promise<TradeStationCashflow[]> {
    try {
      // TradeStation doesn't have a dedicated cashflow endpoint
      // Try to get transactions that include deposits/withdrawals
      const accountKeysParam = accountIds.join(',');

      // Attempt to get order history and filter for cash transactions
      const response = await this.makeRequest<{ Transactions?: Array<{
        TransactionID: string;
        Type: string;
        Amount: number;
        Date: string;
        Description: string;
      }> }>(
        `/v3/brokerage/accounts/${accountKeysParam}/transactions`,
        { since: since.toISOString() }
      );

      if (!response.Transactions) {
        logger.info('TradeStation transactions endpoint not available - cashflows will be empty');
        return [];
      }

      return response.Transactions
        .filter(tx =>
          tx.Type?.toLowerCase().includes('deposit') ||
          tx.Type?.toLowerCase().includes('withdrawal') ||
          tx.Type?.toLowerCase().includes('transfer')
        )
        .map(tx => ({
          id: tx.TransactionID,
          type: tx.Amount > 0 ? 'deposit' as const : 'withdrawal' as const,
          amount: Math.abs(tx.Amount),
          date: new Date(tx.Date),
          description: tx.Description || tx.Type,
        }));
    } catch (error) {
      // Expected to fail - TradeStation may not expose this endpoint
      logger.debug('TradeStation cashflows not available via API');
      return [];
    }
  }

  /**
   * Get aggregated account info (all accounts combined)
   */
  async getAggregatedBalance(): Promise<{
    totalEquity: number;
    totalCash: number;
    totalUnrealizedPnl: number;
    currency: string;
    accounts: TradeStationAccount[];
  } | null> {
    try {
      const accounts = await this.getAccounts();
      if (accounts.length === 0) {
        return null;
      }

      const accountIds = accounts.map(a => a.AccountID);
      const balances = await this.getBalances(accountIds);

      let totalEquity = 0;
      let totalCash = 0;
      let totalUnrealizedPnl = 0;

      for (const balance of balances) {
        totalEquity += balance.Equity || 0;
        totalCash += balance.CashBalance || 0;
        totalUnrealizedPnl += balance.UnrealizedProfitLoss || 0;
      }

      return {
        totalEquity,
        totalCash,
        totalUnrealizedPnl,
        currency: 'USD',
        accounts,
      };
    } catch (error) {
      logger.error('Failed to get TradeStation aggregated balance', error);
      return null;
    }
  }
}
