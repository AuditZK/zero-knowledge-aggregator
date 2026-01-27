import { injectable } from 'tsyringe';
import type { ExchangeCredentials } from '../types';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('CTraderApiService');

/**
 * cTrader Open API Service (Read-only for enclave)
 *
 * Authentication: OAuth 2.0
 * - apiKey = client_id
 * - apiSecret = client_secret
 * - passphrase = access_token (obtained via OAuth flow)
 *
 * API Documentation: https://help.ctrader.com/open-api/
 * Rate limits: 50 req/s (non-historical), 5 req/s (historical)
 */

// cTrader API response types
export interface CTraderAccount {
  ctidTraderAccountId: number;
  isLive: boolean;
  traderLogin: number;
  balance: number;
  balanceVersion: number;
  managerBonus: number;
  ibBonus: number;
  nonWithdrawableBonus: number;
  depositAssetId: number;
  swapFree: boolean;
  leverageInCents: number;
  brokerName: string;
  brokerTitle: string;
}

export interface CTraderPosition {
  positionId: number;
  tradeData: {
    symbolId: number;
    volume: number;  // in cents (divide by 100)
    tradeSide: 'BUY' | 'SELL';
    openTimestamp: number;
    guaranteedStopLoss: boolean;
    usedMargin?: number;
  };
  positionStatus: 'POSITION_STATUS_OPEN' | 'POSITION_STATUS_CLOSED';
  swap: number;
  price: number;  // Entry price in cents
  stopLoss?: number;
  takeProfit?: number;
  utcLastUpdateTimestamp: number;
  commission: number;
  marginRate?: number;
  mirroringCommission?: number;
  guaranteedStopLoss: boolean;
  usedMargin?: number;
  moneyDigits: number;
  unrealizedGrossProfit?: number;  // in cents
  unrealizedNetProfit?: number;    // in cents (after swap/commission)
}

export interface CTraderDeal {
  dealId: number;
  orderId: number;
  positionId: number;
  volume: number;       // in cents
  filledVolume: number; // in cents
  symbolId: number;
  createTimestamp: number;
  executionTimestamp: number;
  utcLastUpdateTimestamp: number;
  executionPrice: number;  // in cents
  tradeSide: 'BUY' | 'SELL';
  dealStatus: 'FILLED' | 'PARTIALLY_FILLED' | 'REJECTED' | 'INTERNALLY_REJECTED' | 'ERROR' | 'MISSED';
  marginRate?: number;
  commission: number;
  baseToUsdConversionRate?: number;
  closePositionDetail?: {
    entryPrice: number;
    grossProfit: number;
    swap: number;
    commission: number;
    balance: number;
    balanceVersion: number;
    quoteToDepositConversionRate?: number;
  };
}

export interface CTraderSymbol {
  symbolId: number;
  symbolName: string;
  digits: number;
  pipPosition: number;
  baseAssetId: number;
  quoteAssetId: number;
}

export interface CTraderCashflow {
  id: number;
  type: 'DEPOSIT' | 'WITHDRAW';
  amount: number;
  timestamp: number;
  externalNote?: string;
}

// OAuth token response
interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
}

@injectable()
export class CTraderApiService {
  private readonly baseUrl = 'https://openapi.ctrader.com';
  private readonly authUrl = 'https://openapi.ctrader.com/apps/auth';
  private accessToken: string;
  private _storedRefreshToken: string; // For future auto-refresh implementation
  private readonly clientId: string;
  private readonly clientSecret: string;
  private accountId: number | null = null;
  private symbolCache: Map<number, CTraderSymbol> = new Map();

  constructor(credentials: ExchangeCredentials) {
    // OAuth flow from frontend sends:
    // - apiKey = access_token
    // - apiSecret = refresh_token
    // - passphrase = expires_in (optional)
    if (!credentials.apiKey) {
      throw new Error('cTrader requires apiKey (access_token from OAuth)');
    }

    this.accessToken = credentials.apiKey;
    // Store refresh token and client credentials for future token refresh
    this._storedRefreshToken = credentials.apiSecret || '';
    this.clientId = process.env.CTRADER_CLIENT_ID || '';
    this.clientSecret = process.env.CTRADER_CLIENT_SECRET || '';

    // Log refresh token availability for debugging (will be used for auto-refresh later)
    if (this._storedRefreshToken) {
      logger.debug('cTrader refresh token available for future token renewal');
    }
  }

  /**
   * Test connection to cTrader
   */
  async testConnection(): Promise<boolean> {
    try {
      const accounts = await this.getAccounts();
      return accounts.length > 0;
    } catch (error) {
      logger.error('cTrader connection test failed', error);
      return false;
    }
  }

  /**
   * Refresh access token using refresh token
   * Note: Requires refresh_token flow - typically done externally
   */
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const response = await fetch(`${this.authUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Token refresh failed: ${error}`);
    }

    const tokenData = await response.json() as TokenResponse;
    this.accessToken = tokenData.access_token;
    return tokenData;
  }

  /**
   * Get all trading accounts linked to cTrader ID
   */
  async getAccounts(): Promise<CTraderAccount[]> {
    const response = await this.makeRequest<{ ctidTraderAccount: CTraderAccount[] }>(
      '/v2/webservices/ctid/ctraderaccounts',
      { accessToken: this.accessToken }
    );

    return response.ctidTraderAccount || [];
  }

  /**
   * Set active account for subsequent requests
   */
  setActiveAccount(accountId: number): void {
    this.accountId = accountId;
  }

  /**
   * Get account balance and equity
   */
  async getAccountBalance(accountId?: number): Promise<{
    balance: number;
    equity: number;
    unrealizedPnl: number;
    currency: string;
    marginUsed: number;
    marginAvailable: number;
  }> {
    const targetAccountId = accountId || this.accountId;
    if (!targetAccountId) {
      throw new Error('No account ID set. Call setActiveAccount() first or provide accountId');
    }

    // Get account details
    const accounts = await this.getAccounts();
    const account = accounts.find(a => a.ctidTraderAccountId === targetAccountId);

    if (!account) {
      throw new Error(`Account ${targetAccountId} not found`);
    }

    // Get open positions to calculate equity
    const positions = await this.getPositions(targetAccountId);
    const unrealizedPnl = positions.reduce((sum, pos) => {
      return sum + (pos.unrealizedNetProfit || 0) / 100; // Convert from cents
    }, 0);

    const marginUsed = positions.reduce((sum, pos) => {
      return sum + (pos.usedMargin || 0) / 100;
    }, 0);

    const balance = account.balance / 100; // Convert from cents
    const equity = balance + unrealizedPnl;

    return {
      balance,
      equity,
      unrealizedPnl,
      currency: 'USD', // cTrader uses deposit asset - simplified to USD
      marginUsed,
      marginAvailable: equity - marginUsed,
    };
  }

  /**
   * Get open positions
   */
  async getPositions(accountId?: number): Promise<CTraderPosition[]> {
    const targetAccountId = accountId || this.accountId;
    if (!targetAccountId) {
      throw new Error('No account ID set');
    }

    const response = await this.makeRequest<{ position: CTraderPosition[] }>(
      `/v2/webservices/trader/${targetAccountId}/positions`,
      { accessToken: this.accessToken }
    );

    return response.position || [];
  }

  /**
   * Get historical deals (closed trades)
   */
  async getDeals(
    accountId: number | undefined,
    fromTimestamp: number,
    toTimestamp: number
  ): Promise<CTraderDeal[]> {
    const targetAccountId = accountId || this.accountId;
    if (!targetAccountId) {
      throw new Error('No account ID set');
    }

    const response = await this.makeRequest<{ deal: CTraderDeal[] }>(
      `/v2/webservices/trader/${targetAccountId}/deals`,
      {
        accessToken: this.accessToken,
        from: fromTimestamp.toString(),
        to: toTimestamp.toString(),
      }
    );

    return response.deal || [];
  }

  /**
   * Get symbol information by ID
   */
  async getSymbol(symbolId: number, accountId?: number): Promise<CTraderSymbol | null> {
    // Check cache first
    if (this.symbolCache.has(symbolId)) {
      return this.symbolCache.get(symbolId)!;
    }

    const targetAccountId = accountId || this.accountId;
    if (!targetAccountId) {
      return null;
    }

    try {
      const response = await this.makeRequest<{ symbol: CTraderSymbol[] }>(
        `/v2/webservices/trader/${targetAccountId}/symbols`,
        { accessToken: this.accessToken, symbolId: symbolId.toString() }
      );

      const symbol = response.symbol?.[0];
      if (symbol) {
        this.symbolCache.set(symbolId, symbol);
      }
      return symbol || null;
    } catch {
      return null;
    }
  }

  /**
   * Get symbol name by ID (with caching)
   */
  async getSymbolName(symbolId: number, accountId?: number): Promise<string> {
    const symbol = await this.getSymbol(symbolId, accountId);
    return symbol?.symbolName || `SYMBOL_${symbolId}`;
  }

  /**
   * Get cash transfers (deposits/withdrawals)
   * Note: This may require additional API access depending on broker
   */
  async getCashflows(accountId: number | undefined, since: Date): Promise<CTraderCashflow[]> {
    const targetAccountId = accountId || this.accountId;
    if (!targetAccountId) {
      return [];
    }

    try {
      const response = await this.makeRequest<{ transaction: CTraderCashflow[] }>(
        `/v2/webservices/trader/${targetAccountId}/cashflows`,
        {
          accessToken: this.accessToken,
          from: since.getTime().toString(),
          to: Date.now().toString(),
        }
      );

      return response.transaction || [];
    } catch (error) {
      // Cashflows may not be available for all brokers
      logger.warn('cTrader cashflows not available', { error: String(error) });
      return [];
    }
  }

  /**
   * Make authenticated request to cTrader REST API
   */
  private async makeRequest<T>(
    endpoint: string,
    params: Record<string, string>
  ): Promise<T> {
    const url = new URL(`${this.baseUrl}${endpoint}`);
    Object.entries(params).forEach(([key, value]) => {
      url.searchParams.append(key, value);
    });

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`cTrader API error ${response.status}: ${errorText}`);
    }

    return response.json() as Promise<T>;
  }
}
