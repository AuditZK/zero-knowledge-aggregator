import { injectable } from 'tsyringe';
import Alpaca from '@alpacahq/alpaca-trade-api';
import type {
  ExchangeCredentials,
  AlpacaPosition as AlpacaPosType,
  AlpacaActivity as AlpacaActivityType,
  AlpacaAccount,
} from '../types';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('AlpacaApiService');

/**
 * Alpaca Markets API Service (Read-only for enclave)
 */
export type AlpacaPosition = AlpacaPosType;
export type AlpacaActivity = AlpacaActivityType;

// Type for raw Alpaca SDK responses
interface AlpacaSDKPosition {
  symbol: string;
  qty: string;
  side: 'long' | 'short';
  market_value: string;
  cost_basis: string;
  unrealized_pl: string;
  unrealized_plpc: string;
  current_price: string;
  avg_entry_price?: string;
  lastday_price?: string;
  change_today?: string;
  asset_class?: string;
}

interface AlpacaSDKActivity {
  id: string;
  activity_type: string;
  transaction_time: string;
  type?: string;
  price?: string;
  qty?: string;
  side?: 'buy' | 'sell';
  symbol?: string;
  order_id?: string;
  order_status?: string;
  leaves_qty?: string;
  cum_qty?: string;
}

@injectable()
export class AlpacaApiService {
  private alpaca: Alpaca;
  private isPaper: boolean;

  constructor(credentials: ExchangeCredentials) {
    // Determine if using paper trading based on API key prefix
    this.isPaper = credentials.apiKey.startsWith('PK');

    this.alpaca = new Alpaca({
      keyId: credentials.apiKey,
      secretKey: credentials.apiSecret,
      paper: this.isPaper,
      // Use production URL for live, paper URL for paper trading
      baseUrl: this.isPaper
        ? 'https://paper-api.alpaca.markets'
        : 'https://api.alpaca.markets',
    });
  }

  /**
   * Test connection to Alpaca
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.alpaca.getAccount();
      return true;
    } catch (error) {
      logger.error('Alpaca connection test failed', error);
      return false;
    }
  }

  /**
   * Get current positions
   */
  async getCurrentPositions(): Promise<AlpacaPosition[]> {
    try {
      const positions = await this.alpaca.getPositions();
      return (positions as AlpacaSDKPosition[]).map((pos) => ({
        symbol: pos.symbol,
        qty: pos.qty,
        side: pos.side,
        market_value: pos.market_value,
        cost_basis: pos.cost_basis,
        unrealized_pl: pos.unrealized_pl,
        unrealized_plpc: pos.unrealized_plpc,
        current_price: pos.current_price,
        lastday_price: pos.lastday_price || '0',
        change_today: pos.change_today || '0',
      }));
    } catch (error) {
      logger.error('Failed to fetch Alpaca positions', error);
      return [];
    }
  }

  /**
   * Get trade history (account activities)
   */
  async getTradeHistory(days: number = 90): Promise<AlpacaActivity[]> {
    try {
      const after = new Date();
      after.setDate(after.getDate() - days);

      // Get fill activities (executed trades)
      const activities = await this.alpaca.getAccountActivities({
        activityTypes: 'FILL',
        after: after.toISOString(),
        direction: 'desc',
        pageSize: 500,
      } as any);

      return (activities as AlpacaSDKActivity[]).map((activity) => ({
        id: activity.id,
        activity_type: activity.activity_type,
        transaction_time: activity.transaction_time,
        type: activity.type || '',
        price: activity.price || '0',
        qty: activity.qty || '0',
        side: activity.side || 'buy',
        symbol: activity.symbol || '',
        leaves_qty: activity.leaves_qty || '0',
        order_id: activity.order_id || '',
        cum_qty: activity.cum_qty || '0',
        order_status: activity.order_status || '',
      }));
    } catch (error) {
      logger.error('Failed to fetch Alpaca trade history:', error);
      return [];
    }
  }

  /**
   * Get account information
   */
  async getAccountInfo(): Promise<AlpacaAccount | null> {
    try {
      const account = await this.alpaca.getAccount();
      return {
        id: account.id || '',
        account_number: account.account_number,
        status: account.status,
        currency: account.currency,
        buying_power: account.buying_power,
        regt_buying_power: account.regt_buying_power || '',
        daytrading_buying_power: account.daytrading_buying_power || '',
        cash: account.cash,
        portfolio_value: account.portfolio_value,
        pattern_day_trader: account.pattern_day_trader,
        trading_blocked: account.trading_blocked,
        transfers_blocked: account.transfers_blocked,
        account_blocked: account.account_blocked,
        created_at: account.created_at,
        trade_suspended_by_user: account.trade_suspended_by_user,
        multiplier: account.multiplier || '',
        shorting_enabled: account.shorting_enabled || false,
        equity: account.equity || '',
        last_equity: account.last_equity || '',
        long_market_value: account.long_market_value || '',
        short_market_value: account.short_market_value || '',
        initial_margin: account.initial_margin || '',
        maintenance_margin: account.maintenance_margin || '',
        last_maintenance_margin: account.last_maintenance_margin || '',
        sma: account.sma || '',
        daytrade_count: account.daytrade_count || 0,
      };
    } catch (error) {
      logger.error('Failed to fetch Alpaca account info:', error);
      return null;
    }
  }
}