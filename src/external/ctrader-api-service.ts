import { injectable } from 'tsyringe';
import WebSocket from 'ws';
import type { ExchangeCredentials } from '../types';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('CTraderApiService');

/**
 * cTrader Open API Service (Read-only for enclave)
 *
 * Uses WebSocket JSON API (port 5036) for full functionality
 * - Positions, equity, and trade history available
 *
 * Authentication: OAuth 2.0
 * - apiKey = access_token (obtained via OAuth flow)
 * - apiSecret = refresh_token (optional)
 *
 * API Documentation: https://help.ctrader.com/open-api/
 * Rate limits: 50 req/s (non-historical), 5 req/s (historical)
 */

// Payload types for cTrader Open API
const PayloadType = {
  // Authentication
  PROTO_OA_APPLICATION_AUTH_REQ: 2100,
  PROTO_OA_APPLICATION_AUTH_RES: 2101,
  PROTO_OA_ACCOUNT_AUTH_REQ: 2102,
  PROTO_OA_ACCOUNT_AUTH_RES: 2103,
  // Account info
  PROTO_OA_GET_ACCOUNTS_BY_ACCESS_TOKEN_REQ: 2149,
  PROTO_OA_GET_ACCOUNTS_BY_ACCESS_TOKEN_RES: 2150,
  PROTO_OA_TRADER_REQ: 2121,
  PROTO_OA_TRADER_RES: 2122,
  // Positions & Orders
  PROTO_OA_RECONCILE_REQ: 2124,
  PROTO_OA_RECONCILE_RES: 2125,
  // Deals (historical trades)
  PROTO_OA_DEAL_LIST_REQ: 2133,
  PROTO_OA_DEAL_LIST_RES: 2134,
  // Cashflow
  PROTO_OA_CASH_FLOW_HISTORY_LIST_REQ: 2143,
  PROTO_OA_CASH_FLOW_HISTORY_LIST_RES: 2144,
  // Symbols
  PROTO_OA_SYMBOL_BY_ID_REQ: 2116,
  PROTO_OA_SYMBOL_BY_ID_RES: 2117,
  // Heartbeat
  PROTO_OA_HEARTBEAT_EVENT: 51,
  // Errors
  PROTO_OA_ERROR_RES: 2142,
} as const;

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

export interface CTraderTrader {
  ctidTraderAccountId: number;
  balance: number;
  balanceVersion: number;
  managerBonus: number;
  ibBonus: number;
  nonWithdrawableBonus: number;
  depositAssetId: number;
  swapFree: boolean;
  leverageInCents: number;
  totalMarginCalculationType: string;
  maxLeverage: number;
  frenchRisk: boolean;
  traderLogin: number;
  accountType: string;
  brokerName: string;
  registrationTimestamp: number;
  isLimitedRisk: boolean;
  limitedRiskMarginCalculationStrategy: string;
  moneyDigits: number;
}

export interface CTraderPosition {
  positionId: number;
  tradeData: {
    symbolId: number;
    volume: number;
    tradeSide: 'BUY' | 'SELL';
    openTimestamp: number;
    guaranteedStopLoss: boolean;
    usedMargin?: number;
  };
  positionStatus: 'POSITION_STATUS_OPEN' | 'POSITION_STATUS_CLOSED';
  swap: number;
  price: number;
  stopLoss?: number;
  takeProfit?: number;
  utcLastUpdateTimestamp: number;
  commission: number;
  marginRate?: number;
  mirroringCommission?: number;
  guaranteedStopLoss: boolean;
  usedMargin?: number;
  moneyDigits: number;
  unrealizedGrossProfit?: number;
  unrealizedNetProfit?: number;
}

export interface CTraderDeal {
  dealId: number;
  orderId: number;
  positionId: number;
  volume: number;
  filledVolume: number;
  symbolId: number;
  createTimestamp: number;
  executionTimestamp: number;
  utcLastUpdateTimestamp: number;
  executionPrice: number;
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

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  expectedPayloadType: number;
}

@injectable()
export class CTraderApiService {
  // WebSocket endpoints for JSON API (port 5036)
  private readonly wsLiveUrl = 'wss://live.ctraderapi.com:5036';
  private readonly wsDemoUrl = 'wss://demo.ctraderapi.com:5036';
  private readonly authUrl = 'https://openapi.ctrader.com/apps';

  private ws: WebSocket | null = null;
  private accessToken: string;
  private readonly refreshTokenValue: string | null;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private accountId: number | null = null;
  private isLive: boolean = true;
  private symbolCache: Map<number, CTraderSymbol> = new Map();
  private pendingRequests: Map<string, PendingRequest> = new Map();
  private msgIdCounter = 0;
  private isConnected = false;
  private isAppAuthenticated = false;
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;

  constructor(credentials: ExchangeCredentials) {
    if (!credentials.apiKey) {
      throw new Error('cTrader requires apiKey (access_token from OAuth)');
    }

    this.accessToken = credentials.apiKey;
    this.refreshTokenValue = credentials.apiSecret || null;
    this.clientId = process.env.CTRADER_CLIENT_ID || '';
    this.clientSecret = process.env.CTRADER_CLIENT_SECRET || '';

    // Determine if live or demo based on passphrase or default to live
    this.isLive = credentials.passphrase !== 'demo';
  }

  getIsLive(): boolean {
    return this.isLive;
  }

  /**
   * Connect to cTrader WebSocket API
   */
  private async connect(): Promise<void> {
    if (this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    return new Promise((resolve, reject) => {
      const url = this.isLive ? this.wsLiveUrl : this.wsDemoUrl;
      logger.info(`Connecting to cTrader WebSocket: ${this.isLive ? 'LIVE' : 'DEMO'}`);

      this.ws = new WebSocket(url);

      const timeout = setTimeout(() => {
        reject(new Error('cTrader WebSocket connection timeout'));
        this.ws?.close();
      }, 10000);

      this.ws.on('open', () => {
        clearTimeout(timeout);
        this.isConnected = true;
        logger.info('cTrader WebSocket connected');
        this.startHeartbeat();
        resolve();
      });

      this.ws.on('message', (data: WebSocket.Data) => {
        this.handleMessage(data);
      });

      this.ws.on('error', (error: Error) => {
        clearTimeout(timeout);
        logger.error('cTrader WebSocket error', { error: String(error) });
        reject(error);
      });

      this.ws.on('close', () => {
        this.isConnected = false;
        this.isAppAuthenticated = false;
        this.stopHeartbeat();
        logger.info('cTrader WebSocket disconnected');
      });
    });
  }

  /**
   * Handle incoming WebSocket messages
   */
  private handleMessage(data: WebSocket.Data): void {
    try {
      const message = JSON.parse(data.toString());
      const { clientMsgId, payloadType, payload } = message;

      // Handle heartbeat
      if (payloadType === PayloadType.PROTO_OA_HEARTBEAT_EVENT) {
        return;
      }

      // Handle error responses
      if (payloadType === PayloadType.PROTO_OA_ERROR_RES) {
        const pending = clientMsgId ? this.pendingRequests.get(clientMsgId) : null;
        const errorMsg = payload?.errorCode
          ? `cTrader error ${payload.errorCode}: ${payload.description || 'Unknown error'}`
          : 'cTrader unknown error';

        if (pending) {
          this.pendingRequests.delete(clientMsgId);
          pending.reject(new Error(errorMsg));
        } else {
          logger.error('cTrader error event', { payload });
        }
        return;
      }

      // Handle pending request responses
      if (clientMsgId && this.pendingRequests.has(clientMsgId)) {
        const pending = this.pendingRequests.get(clientMsgId)!;
        this.pendingRequests.delete(clientMsgId);
        pending.resolve(payload);
      }
    } catch (error) {
      logger.error('Failed to parse cTrader message', { error: String(error) });
    }
  }

  /**
   * Send a message and wait for response
   */
  private async sendMessage<T>(
    payloadType: number,
    payload: Record<string, unknown>,
    expectedResponseType: number
  ): Promise<T> {
    await this.connect();

    const clientMsgId = `msg_${++this.msgIdCounter}_${Date.now()}`;
    const message = JSON.stringify({ clientMsgId, payloadType, payload });

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(clientMsgId);
        reject(new Error(`cTrader request timeout for payloadType ${payloadType}`));
      }, 30000);

      this.pendingRequests.set(clientMsgId, {
        resolve: (value) => {
          clearTimeout(timeout);
          resolve(value as T);
        },
        reject: (error) => {
          clearTimeout(timeout);
          reject(error);
        },
        expectedPayloadType: expectedResponseType,
      });

      this.ws!.send(message);
    });
  }

  /**
   * Start heartbeat to keep connection alive
   */
  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          payloadType: PayloadType.PROTO_OA_HEARTBEAT_EVENT,
          payload: {},
        }));
      }
    }, 10000); // Send heartbeat every 10 seconds
  }

  /**
   * Stop heartbeat
   */
  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  /**
   * Authenticate the application
   */
  private async authenticateApp(): Promise<void> {
    if (this.isAppAuthenticated) return;

    if (!this.clientId || !this.clientSecret) {
      throw new Error('cTrader requires CTRADER_CLIENT_ID and CTRADER_CLIENT_SECRET environment variables');
    }

    await this.sendMessage(
      PayloadType.PROTO_OA_APPLICATION_AUTH_REQ,
      { clientId: this.clientId, clientSecret: this.clientSecret },
      PayloadType.PROTO_OA_APPLICATION_AUTH_RES
    );

    this.isAppAuthenticated = true;
    logger.info('cTrader application authenticated');
  }

  /**
   * Authenticate a trading account (auto-refreshes expired tokens)
   */
  private async authenticateAccount(ctidTraderAccountId: number): Promise<void> {
    await this.authenticateApp();

    try {
      await this.sendMessage(
        PayloadType.PROTO_OA_ACCOUNT_AUTH_REQ,
        { ctidTraderAccountId, accessToken: this.accessToken },
        PayloadType.PROTO_OA_ACCOUNT_AUTH_RES
      );
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      if (msg.includes('CH_ACCESS_TOKEN_INVALID') && this.refreshTokenValue) {
        logger.info('Access token expired, attempting refresh...');
        await this.refreshToken(this.refreshTokenValue);

        // Reconnect with new token
        this.disconnect();
        await this.connect();
        await this.authenticateApp();

        await this.sendMessage(
          PayloadType.PROTO_OA_ACCOUNT_AUTH_REQ,
          { ctidTraderAccountId, accessToken: this.accessToken },
          PayloadType.PROTO_OA_ACCOUNT_AUTH_RES
        );

        logger.info('cTrader account authenticated after token refresh');
        return;
      }
      throw error;
    }

    logger.debug('cTrader account authenticated', { ctidTraderAccountId });
  }

  /**
   * Test connection to cTrader
   */
  async testConnection(): Promise<boolean> {
    try {
      const accounts = await this.getAccounts();
      return accounts.length > 0;
    } catch (error) {
      logger.error('cTrader connection test failed', { error: String(error) });
      return false;
    }
  }

  /**
   * Get all trading accounts linked to access token
   */
  async getAccounts(): Promise<CTraderAccount[]> {
    await this.connect();
    await this.authenticateApp();

    try {
      const response = await this.sendMessage<{ ctidTraderAccount?: CTraderAccount[] }>(
        PayloadType.PROTO_OA_GET_ACCOUNTS_BY_ACCESS_TOKEN_REQ,
        { accessToken: this.accessToken },
        PayloadType.PROTO_OA_GET_ACCOUNTS_BY_ACCESS_TOKEN_RES
      );
      return response.ctidTraderAccount || [];
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      if (msg.includes('CH_ACCESS_TOKEN_INVALID') && this.refreshTokenValue) {
        logger.info('Access token expired during getAccounts, attempting refresh...');
        await this.refreshToken(this.refreshTokenValue);

        this.disconnect();
        await this.connect();
        await this.authenticateApp();

        const response = await this.sendMessage<{ ctidTraderAccount?: CTraderAccount[] }>(
          PayloadType.PROTO_OA_GET_ACCOUNTS_BY_ACCESS_TOKEN_REQ,
          { accessToken: this.accessToken },
          PayloadType.PROTO_OA_GET_ACCOUNTS_BY_ACCESS_TOKEN_RES
        );
        return response.ctidTraderAccount || [];
      }
      throw error;
    }
  }

  /**
   * Set active account for subsequent requests
   */
  setActiveAccount(accountId: number): void {
    this.accountId = accountId;
  }

  /**
   * Get trader info (balance, equity data)
   */
  async getTraderInfo(accountId?: number): Promise<CTraderTrader> {
    const targetAccountId = accountId || this.accountId;
    if (!targetAccountId) {
      throw new Error('No account ID set. Call setActiveAccount() first or provide accountId');
    }

    await this.authenticateAccount(targetAccountId);

    const response = await this.sendMessage<{ trader: CTraderTrader }>(
      PayloadType.PROTO_OA_TRADER_REQ,
      { ctidTraderAccountId: targetAccountId },
      PayloadType.PROTO_OA_TRADER_RES
    );

    return response.trader;
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

    // Get trader info for balance
    const trader = await this.getTraderInfo(targetAccountId);
    const moneyDigits = trader.moneyDigits || 2;
    const divisor = Math.pow(10, moneyDigits);

    // Get positions for unrealized P&L
    const positions = await this.getPositions(targetAccountId);
    const unrealizedPnl = positions.reduce((sum, pos) => {
      return sum + (pos.unrealizedNetProfit || 0) / divisor;
    }, 0);

    const marginUsed = positions.reduce((sum, pos) => {
      return sum + (pos.usedMargin || 0) / divisor;
    }, 0);

    const balance = trader.balance / divisor;
    const equity = balance + unrealizedPnl;

    return {
      balance,
      equity,
      unrealizedPnl,
      currency: 'USD', // Simplified - would need asset lookup for actual currency
      marginUsed,
      marginAvailable: equity - marginUsed,
    };
  }

  /**
   * Get open positions using reconcile request
   */
  async getPositions(accountId?: number): Promise<CTraderPosition[]> {
    const targetAccountId = accountId || this.accountId;
    if (!targetAccountId) {
      throw new Error('No account ID set');
    }

    await this.authenticateAccount(targetAccountId);

    const response = await this.sendMessage<{ position?: CTraderPosition[] }>(
      PayloadType.PROTO_OA_RECONCILE_REQ,
      { ctidTraderAccountId: targetAccountId },
      PayloadType.PROTO_OA_RECONCILE_RES
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

    await this.authenticateAccount(targetAccountId);

    const response = await this.sendMessage<{ deal?: CTraderDeal[] }>(
      PayloadType.PROTO_OA_DEAL_LIST_REQ,
      {
        ctidTraderAccountId: targetAccountId,
        fromTimestamp,
        toTimestamp,
        maxRows: 1000,
      },
      PayloadType.PROTO_OA_DEAL_LIST_RES
    );

    return response.deal || [];
  }

  /**
   * Get symbol information by ID
   */
  async getSymbol(symbolId: number, accountId?: number): Promise<CTraderSymbol | null> {
    if (this.symbolCache.has(symbolId)) {
      return this.symbolCache.get(symbolId)!;
    }

    const targetAccountId = accountId || this.accountId;
    if (!targetAccountId) {
      return null;
    }

    try {
      await this.authenticateAccount(targetAccountId);

      const response = await this.sendMessage<{ symbol?: CTraderSymbol[] }>(
        PayloadType.PROTO_OA_SYMBOL_BY_ID_REQ,
        { ctidTraderAccountId: targetAccountId, symbolId: [symbolId] },
        PayloadType.PROTO_OA_SYMBOL_BY_ID_RES
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
   */
  async getCashflows(accountId: number | undefined, since: Date): Promise<CTraderCashflow[]> {
    const targetAccountId = accountId || this.accountId;
    if (!targetAccountId) {
      return [];
    }

    try {
      await this.authenticateAccount(targetAccountId);

      const response = await this.sendMessage<{ depositWithdraw?: CTraderCashflow[] }>(
        PayloadType.PROTO_OA_CASH_FLOW_HISTORY_LIST_REQ,
        {
          ctidTraderAccountId: targetAccountId,
          fromTimestamp: since.getTime(),
          toTimestamp: Date.now(),
        },
        PayloadType.PROTO_OA_CASH_FLOW_HISTORY_LIST_RES
      );

      return response.depositWithdraw || [];
    } catch (error) {
      logger.warn('cTrader cashflows not available', { error: String(error) });
      return [];
    }
  }

  /**
   * Close WebSocket connection
   */
  disconnect(): void {
    this.stopHeartbeat();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.isConnected = false;
    this.isAppAuthenticated = false;
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(refreshToken: string): Promise<{ access_token: string; expires_in: number }> {
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

    const tokenData = await response.json() as { access_token: string; expires_in: number };
    this.accessToken = tokenData.access_token;
    return tokenData;
  }
}
