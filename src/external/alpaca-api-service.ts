import { injectable } from 'tsyringe';
import Alpaca from '@alpacahq/alpaca-trade-api';
import type {
  ExchangeCredentials,
  AlpacaPosition as AlpacaPosType,
  AlpacaOrder as AlpacaOrderType,
  AlpacaActivity as AlpacaActivityType,
  AlpacaAccount,
  AlpacaPortfolioHistory,
  AlpacaMarketData,
} from '../types';
import { getLogger } from '../utils/logger.service';

const logger = getLogger('AlpacaApiService');

/**
 * Alpaca Markets API Service
 * Supports Stocks, Crypto, and Options trading
 */

// Re-export types for backward compatibility
export type AlpacaPosition = AlpacaPosType;
export type AlpacaOrder = AlpacaOrderType;
export type AlpacaActivity = AlpacaActivityType;

export interface AlpacaTrade {
  symbol: string;
  order_id: string;
  id: string; // Trade ID
  side: 'buy' | 'sell';
  qty: string;
  price: string;
  transaction_time: string;
  type?: string;
}

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
  asset_id?: string;
}

interface AlpacaSDKOrder {
  id: string;
  status: string;
  filled_at?: string | null;
  symbol?: string;
  qty?: string;
  filled_qty?: string;
  side?: 'buy' | 'sell';
  filled_avg_price?: string | null;
  created_at?: string;
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

  constructor(private credentials: ExchangeCredentials) {
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
      const account = await this.alpaca.getAccount();
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
   * Get closed positions (from orders history)
   */
  async getClosedPositions(days: number = 90): Promise<AlpacaSDKOrder[]> {
    try {
      const after = new Date();
      after.setDate(after.getDate() - days);

      const orders = await this.alpaca.getOrders({
        status: 'closed', // Only get filled orders
        after: after.toISOString(),
        direction: 'desc',
        limit: 500,
      });

      return (orders as AlpacaSDKOrder[]).filter((order) => order.status === 'filled');
    } catch (error) {
      logger.error('Failed to fetch Alpaca closed positions:', error);
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
        activity_types: 'FILL',
        after: after.toISOString(),
        direction: 'desc',
        page_size: 500,
      });

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
   * Get all orders (including partial fills)
   */
  async getAllOrders(days: number = 90): Promise<AlpacaOrder[]> {
    try {
      const after = new Date();
      after.setDate(after.getDate() - days);

      const orders = await this.alpaca.getOrders({
        status: 'all',
        after: after.toISOString(),
        direction: 'desc',
        limit: 500,
      });

      return (orders as AlpacaSDKOrder[]).map((order) => ({
        id: order.id,
        client_order_id: order.id,
        created_at: order.created_at || '',
        updated_at: order.created_at || '',
        submitted_at: order.created_at || '',
        filled_at: order.filled_at || null,
        expired_at: null,
        canceled_at: null,
        failed_at: null,
        replaced_at: null,
        replaced_by: null,
        replaces: null,
        asset_id: '',
        symbol: order.symbol || '',
        asset_class: '',
        qty: order.qty || '0',
        filled_qty: order.filled_qty || '0',
        type: '',
        side: order.side || 'buy',
        time_in_force: '',
        limit_price: null,
        stop_price: null,
        filled_avg_price: order.filled_avg_price || null,
        status: order.status,
        extended_hours: false,
        legs: null,
      }));
    } catch (error) {
      logger.error('Failed to fetch Alpaca orders:', error);
      return [];
    }
  }

  /**
   * Get portfolio history
   */
  async getPortfolioHistory(period: string = '1M', timeframe: string = '1D'): Promise<AlpacaPortfolioHistory | null> {
    try {
      const history = await this.alpaca.getPortfolioHistory({
        period, // 1D, 1W, 1M, 3M, 6M, 1Y, all
        timeframe, // 1Min, 5Min, 15Min, 1H, 1D
      });

      return {
        timestamp: history.timestamps,
        equity: history.equity,
        profit_loss: history.profit_loss,
        profit_loss_pct: history.profit_loss_pct,
        base_value: history.base_value,
        timeframe: history.timeframe,
      };
    } catch (error) {
      logger.error('Failed to fetch Alpaca portfolio history:', error);
      return null;
    }
  }

  /**
   * Get account information
   */
  async getAccountInfo(): Promise<AlpacaAccount | null> {
    try {
      const account = await this.alpaca.getAccount();
      return {
        account_number: account.account_number,
        status: account.status,
        currency: account.currency,
        buying_power: account.buying_power,
        cash: account.cash,
        portfolio_value: account.portfolio_value,
        pattern_day_trader: account.pattern_day_trader,
        trading_blocked: account.trading_blocked,
        transfers_blocked: account.transfers_blocked,
        account_blocked: account.account_blocked,
        trade_suspended_by_user: account.trade_suspended_by_user,
        created_at: account.created_at,
      };
    } catch (error) {
      logger.error('Failed to fetch Alpaca account info:', error);
      return null;
    }
  }

  /**
   * Place an order
   */
  async placeOrder(
    symbol: string,
    qty: number,
    side: 'buy' | 'sell',
    type: 'market' | 'limit',
    limitPrice?: number,
  ): Promise<string | null> {
    try {
      const order = await this.alpaca.createOrder({
        symbol,
        qty,
        side,
        type,
        time_in_force: 'day',
        limit_price: limitPrice,
      });

      return order.id;
    } catch (error) {
      logger.error('Failed to place Alpaca order:', error);
      return null;
    }
  }

  /**
   * Cancel an order
   */
  async cancelOrder(orderId: string): Promise<boolean> {
    try {
      await this.alpaca.cancelOrder(orderId);
      return true;
    } catch (error) {
      logger.error('Failed to cancel Alpaca order:', error);
      return false;
    }
  }

  /**
   * Get market data for a symbol
   */
  async getMarketData(symbol: string): Promise<Partial<AlpacaMarketData> | null> {
    try {
      // Get latest trade
      const latestTrade = await this.alpaca.getLatestTrade(symbol);

      // Get latest quote
      const latestQuote = await this.alpaca.getLatestQuote(symbol);

      return {
        symbol,
        latest_trade: {
          t: latestTrade.Timestamp,
          x: '',
          p: latestTrade.Price,
          s: latestTrade.Size,
          c: [],
          i: 0,
          z: '',
        },
        latest_quote: {
          t: latestQuote.Timestamp,
          ax: '',
          ap: latestQuote.AskPrice,
          as: latestQuote.AskSize,
          bx: '',
          bp: latestQuote.BidPrice,
          bs: latestQuote.BidSize,
          c: [],
        },
      };
    } catch (error) {
      logger.error('Failed to fetch Alpaca market data:', error);
      return null;
    }
  }

  /**
   * Get historical bars
   */
  async getHistoricalBars(
    symbol: string,
    start: Date,
    end: Date,
    timeframe: string = '1Day',
  ): Promise<Array<{ timestamp: string; open: number; high: number; low: number; close: number; volume: number }>> {
    try {
      const bars = await this.alpaca.getBarsV2(
        symbol,
        {
          start: start.toISOString(),
          end: end.toISOString(),
          timeframe, // 1Min, 5Min, 15Min, 1Hour, 1Day
          limit: 1000,
        },
      );

      const result = [];
      for await (const bar of bars) {
        result.push({
          timestamp: bar.Timestamp,
          open: bar.OpenPrice,
          high: bar.HighPrice,
          low: bar.LowPrice,
          close: bar.ClosePrice,
          volume: bar.Volume,
        });
      }

      return result;
    } catch (error) {
      logger.error('Failed to fetch Alpaca historical bars:', error);
      return [];
    }
  }
}

/**
 * Configuration notes for Alpaca:
 *
 * 1. Get API keys from: https://app.alpaca.markets
 * 2. Paper trading keys start with 'PK', live keys start with 'AK'
 * 3. Supports: US Stocks, ETFs, Crypto
 * 4. Market hours: 9:30 AM - 4:00 PM ET (stocks), 24/7 (crypto)
 * 5. No minimum balance for paper trading
 * 6. $0 minimum for live trading (but need to fund account)
 */