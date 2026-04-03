import { BaseExchangeConnector } from '../external/base/BaseExchangeConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
  ExchangeFeature,
} from '../external/interfaces/IExchangeConnector';
import { ExchangeCredentials } from '../types';
import crypto from 'node:crypto';

/**
 * MetaTrader 4/5 Connector
 *
 * Delegates to the mt-bridge Go service for native MT4/MT5 TCP protocol communication.
 * The mt-bridge connects directly to broker MT servers (no Wine, no terminal required).
 *
 * Credentials mapping:
 *   apiKey     = MT login number (as string, e.g. "12345678")
 *   apiSecret  = investor password (read-only access)
 *   passphrase = broker server address (e.g. "ICMarketsSC-Live02:443")
 *
 * The mt-bridge service runs on the VPS Docker network and is accessed via HTTP.
 * Communication is authenticated with HMAC-SHA256 shared secret.
 */
export class MetaTraderConnector extends BaseExchangeConnector {
  private readonly mtBridgeUrl: string;
  private readonly hmacSecret: string;
  private readonly mtLogin: number;
  private readonly investorPassword: string;
  private readonly brokerServer: string;
  private readonly protocol: 'mt4' | 'mt5';
  private sessionId: string | null = null;

  constructor(credentials: ExchangeCredentials) {
    super(credentials);

    this.mtBridgeUrl = process.env.MT_BRIDGE_URL || 'http://mt-bridge:8090';
    this.hmacSecret = process.env.MT_BRIDGE_HMAC_SECRET || '';

    this.mtLogin = parseInt(credentials.apiKey, 10);
    this.investorPassword = credentials.apiSecret;
    this.brokerServer = credentials.passphrase || '';
    this.protocol = credentials.exchange === 'mt5' ? 'mt5' : 'mt4';

    if (!this.mtLogin || !this.investorPassword || !this.brokerServer) {
      throw new Error(
        'MetaTrader requires login (apiKey), investor password (apiSecret), and server address (passphrase)'
      );
    }
  }

  getExchangeName(): string {
    return this.protocol;
  }

  supportsFeature(feature: ExchangeFeature): boolean {
    return (['positions', 'trades'] as ExchangeFeature[]).includes(feature);
  }

  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      await this.ensureConnected();

      const resp = await this.callBridge<{
        balance: number;
        equity: number;
        unrealized_pnl: number;
        currency: string;
        margin_used: number;
        margin_free: number;
        leverage: number;
      }>('GET', `/api/v1/sessions/${this.sessionId}/account-info`);

      // MT5 bridge may return equity = balance (server quirk), so recalculate
      const unrealizedPnl = resp.unrealized_pnl || 0;
      const equity = unrealizedPnl !== 0 ? resp.balance + unrealizedPnl : resp.equity;

      return {
        balance: resp.balance,
        equity,
        unrealizedPnl,
        currency: resp.currency || 'USD',
        marginUsed: resp.margin_used,
        marginAvailable: resp.margin_free,
      };
    });
  }

  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      await this.ensureConnected();

      const resp = await this.callBridge<
        Array<{
          ticket: number;
          symbol: string;
          side: string;
          size: number;
          entry_price: number;
          mark_price: number;
          unrealized_pnl: number;
          swap: number;
          commission: number;
        }>
      >('GET', `/api/v1/sessions/${this.sessionId}/positions`);

      if (!resp) return [];

      return resp.map((p) => ({
        symbol: p.symbol,
        side: p.side as 'long' | 'short',
        size: p.size,
        entryPrice: p.entry_price,
        markPrice: p.mark_price,
        unrealizedPnl: p.unrealized_pnl + (p.swap || 0) + (p.commission || 0),
      }));
    });
  }

  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      await this.ensureConnected();

      const from = Math.floor(startDate.getTime() / 1000);
      const to = Math.floor(endDate.getTime() / 1000);

      const resp = await this.callBridge<
        Array<{
          ticket: number;
          symbol: string;
          side: string;
          size: number;
          open_price: number;
          close_price: number;
          realized_pnl: number;
          commission: number;
          swap: number;
          close_time: string;
        }>
      >('GET', `/api/v1/sessions/${this.sessionId}/history-deals?from=${from}&to=${to}`);

      if (!resp) return [];

      return resp
        .filter((d) => d.symbol !== 'BALANCE')
        .map((d) => ({
          tradeId: String(d.ticket),
          symbol: d.symbol,
          side: d.side as 'buy' | 'sell',
          quantity: d.size,
          price: d.close_price || d.open_price,
          fee: Math.abs(d.commission || 0) + Math.abs(d.swap || 0),
          feeCurrency: 'USD',
          timestamp: new Date(d.close_time),
          realizedPnl: d.realized_pnl,
        }));
    });
  }

  async getCashflows(since: Date): Promise<{ deposits: number; withdrawals: number }> {
    return this.withErrorHandling('getCashflows', async () => {
      await this.ensureConnected();

      const from = Math.floor(since.getTime() / 1000);
      const to = Math.floor(Date.now() / 1000);

      const resp = await this.callBridge<
        Array<{
          ticket: number;
          symbol: string;
          side: string;
          realized_pnl: number;
          close_time: string;
        }>
      >('GET', `/api/v1/sessions/${this.sessionId}/history-deals?from=${from}&to=${to}`);

      if (!resp) return { deposits: 0, withdrawals: 0 };

      let deposits = 0;
      let withdrawals = 0;

      for (const deal of resp) {
        if (deal.symbol !== 'BALANCE') continue;
        if (deal.side === 'deposit') {
          deposits += deal.realized_pnl;
        } else if (deal.side === 'withdrawal') {
          withdrawals += Math.abs(deal.realized_pnl);
        }
      }

      return { deposits, withdrawals };
    });
  }

  async getCashflowsByDate(since: Date): Promise<Map<string, { deposits: number; withdrawals: number }>> {
    return this.withErrorHandling('getCashflowsByDate', async () => {
      await this.ensureConnected();

      const from = Math.floor(since.getTime() / 1000);
      const to = Math.floor(Date.now() / 1000);

      const resp = await this.callBridge<
        Array<{
          ticket: number;
          symbol: string;
          side: string;
          realized_pnl: number;
          close_time: string;
        }>
      >('GET', `/api/v1/sessions/${this.sessionId}/history-deals?from=${from}&to=${to}`);

      const result = new Map<string, { deposits: number; withdrawals: number }>();
      if (!resp) return result;

      for (const deal of resp) {
        if (deal.symbol !== 'BALANCE') continue;
        const dateKey = deal.close_time.split('T')[0].replace(/-/g, '');
        const entry = result.get(dateKey) || { deposits: 0, withdrawals: 0 };
        if (deal.side === 'deposit') {
          entry.deposits += deal.realized_pnl;
        } else if (deal.side === 'withdrawal') {
          entry.withdrawals += Math.abs(deal.realized_pnl);
        }
        result.set(dateKey, entry);
      }

      return result;
    });
  }

  // ========================================
  // Private helpers
  // ========================================

  private async ensureConnected(): Promise<void> {
    if (this.sessionId) return;

    const body = JSON.stringify({
      protocol: this.protocol,
      server: this.brokerServer,
      login: this.mtLogin,
      password: this.investorPassword,
    });

    const result = await this.callBridge<{
      session_id: string;
      server_name: string;
      trade_mode: string;
    }>('POST', '/api/v1/connect', body);

    this.sessionId = result.session_id;
    this.logger.info(
      `MetaTrader connected: login=${this.mtLogin}, server=${result.server_name}, mode=${result.trade_mode}`
    );
  }

  private async callBridge<T>(method: string, path: string, body?: string): Promise<T> {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const payload = timestamp + '.' + (body || '');
    const signature = crypto
      .createHmac('sha256', this.hmacSecret)
      .update(payload)
      .digest('hex');

    const response = await fetch(`${this.mtBridgeUrl}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-MT-Bridge-Timestamp': timestamp,
        'X-MT-Bridge-Signature': signature,
      },
      body: method !== 'GET' && method !== 'DELETE' ? body : undefined,
    });

    const json = (await response.json()) as {
      success: boolean;
      data?: T;
      error?: { code: string; message: string };
    };

    if (!json.success) {
      // Session expired or bridge restarted — reconnect and retry once
      if (json.error?.code === 'SESSION_NOT_FOUND' && this.sessionId) {
        this.logger.warn('Session expired, reconnecting...');
        this.sessionId = null;
        await this.ensureConnected();
        return this.callBridge<T>(method, path.replace(/sessions\/[^/]+/, `sessions/${this.sessionId}`), body);
      }
      throw new Error(
        `mt-bridge [${json.error?.code || 'UNKNOWN'}]: ${json.error?.message || 'Unknown error'}`
      );
    }

    return json.data as T;
  }
}
