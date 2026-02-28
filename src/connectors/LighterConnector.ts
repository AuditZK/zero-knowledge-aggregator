import { CryptoExchangeConnector } from '../external/base/CryptoExchangeConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
} from '../external/interfaces/IExchangeConnector';
import { ExchangeCredentials } from '../types';
import {
  MarketBalanceData,
  ExecutedOrderData,
  MarketType,
} from '../types/snapshot-breakdown';

/** Lighter API base URL (mainnet) */
const LIGHTER_API_URL = 'https://mainnet.zklighter.elliot.ai';

/** Lighter account API response */
interface LighterAccountResponse {
  code: number;
  message: string;
  total: number;
  accounts: LighterDetailedAccount[];
}

interface LighterDetailedAccount {
  index: number;
  l1_address: string;
  account_type: number;
  available_balance: string;
  collateral: string;
  total_asset_value: string;
  cross_asset_value: string;
  status: number;
  positions: LighterPosition[];
  assets: LighterAsset[];
}

interface LighterPosition {
  market_id: number;
  symbol: string;
  sign: number; // 1 = long, -1 = short
  size: string;
  avg_entry_price: string;
  position_value: string;
  unrealized_pnl: string;
  realized_pnl: string;
  liquidation_price: string;
  initial_margin_fraction: number;
  maintenance_margin_fraction: number;
  open_order_count: number;
  isolated_open_order_count: number;
}

interface LighterAsset {
  symbol: string;
  asset_id: number;
  balance: string;
  locked_balance: string;
}

/** Lighter trades API response */
interface LighterTradesResponse {
  code: number;
  message: string;
  next_cursor: string;
  trades: LighterTrade[];
}

interface LighterTrade {
  trade_id: number;
  tx_hash: string;
  type: 'trade' | 'liquidation' | 'deleverage';
  market_id: number;
  size: string;
  price: string;
  usd_amount: string;
  ask_id: number;
  bid_id: number;
  ask_account_id: number;
  bid_account_id: number;
  is_maker_ask: boolean;
  block_height: number;
  timestamp: number;
  taker_fee: number;
  maker_fee: number;
}

/**
 * Lighter DEX Connector
 *
 * Connects to Lighter's REST API for reading account data.
 * No private key required for read-only operations (balance, positions, trades).
 *
 * API Reference: https://apidocs.lighter.xyz
 *
 * Credentials:
 * - apiKey: Wallet address (0x...)
 * - apiSecret: Not required (read-only)
 */
export class LighterConnector extends CryptoExchangeConnector {
  private readonly walletAddress: string;
  private readonly apiUrl: string;
  private accountIndex: number | null = null;

  constructor(credentials: ExchangeCredentials) {
    super(credentials);

    if (!credentials.apiKey?.startsWith('0x')) {
      throw new Error('Lighter requires a valid wallet address (0x...) as apiKey');
    }

    this.walletAddress = credentials.apiKey;
    this.apiUrl = LIGHTER_API_URL;

    this.logger.info('Lighter connector initialized');
  }

  getExchangeName(): string {
    return 'lighter';
  }

  /** Connected to mainnet (mainnet.zklighter.elliot.ai) — always live. */
  async detectIsPaper(): Promise<boolean> {
    return false;
  }

  /**
   * Get account balance
   */
  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      const account = await this.fetchAccount();

      const available = Number.parseFloat(account.available_balance) || 0;
      const equity = Number.parseFloat(account.total_asset_value) || 0;
      const collateral = Number.parseFloat(account.collateral) || 0;

      return {
        balance: collateral,
        equity,
        unrealizedPnl: equity - collateral,
        currency: 'USDC',
        marginUsed: collateral - available,
        marginAvailable: available,
      };
    });
  }

  /**
   * Get current open positions
   */
  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      const account = await this.fetchAccount();

      return account.positions
        .filter(pos => {
          const size = Number.parseFloat(pos.size);
          return size !== 0;
        })
        .map(pos => this.mapPosition(pos));
    });
  }

  /**
   * Get trade history
   */
  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      const accountIndex = await this.getAccountIndex();
      const trades = await this.fetchAllTrades(accountIndex);

      return trades
        .filter(trade => {
          const tradeDate = new Date(trade.timestamp * 1000);
          return this.isInDateRange(tradeDate, startDate, endDate);
        })
        .map(trade => this.mapTrade(trade, accountIndex));
    });
  }

  /**
   * Test connection by fetching account data
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.fetchAccount();
      this.logger.info('Lighter: Connection test successful');
      return true;
    } catch (error) {
      this.logger.error('Lighter: Connection test failed', { error: String(error) });
      return false;
    }
  }

  /**
   * Detect available market types
   * Lighter supports perpetual futures only
   */
  async detectMarketTypes(): Promise<MarketType[]> {
    return ['swap'];
  }

  /**
   * Get balance breakdown by market type
   */
  async getBalanceByMarket(marketType: MarketType): Promise<MarketBalanceData> {
    return this.withErrorHandling('getBalanceByMarket', async () => {
      if (marketType !== 'swap') {
        return { equity: 0, available_margin: 0 };
      }

      const account = await this.fetchAccount();
      const equity = Number.parseFloat(account.total_asset_value) || 0;
      const availableMargin = Number.parseFloat(account.available_balance) || 0;
      const collateral = Number.parseFloat(account.collateral) || 0;

      return { equity, available_margin: availableMargin, margin_used: collateral - availableMargin };
    });
  }

  /**
   * Get executed orders for snapshot aggregation
   */
  async getExecutedOrders(marketType: MarketType, since: Date): Promise<ExecutedOrderData[]> {
    return this.withErrorHandling('getExecutedOrders', async () => {
      if (marketType !== 'swap') {
        return [];
      }

      const accountIndex = await this.getAccountIndex();
      const trades = await this.fetchAllTrades(accountIndex);
      const sinceMs = since.getTime();

      return trades
        .filter(trade => trade.timestamp * 1000 >= sinceMs)
        .map(trade => this.mapExecutedOrder(trade, accountIndex));
    });
  }

  // ========================================
  // Private API methods
  // ========================================

  /**
   * Fetch account data by wallet address
   */
  private async fetchAccount(): Promise<LighterDetailedAccount> {
    const response = await this.makeRequest<LighterAccountResponse>('/api/v1/account', {
      by: 'l1_address',
      value: this.walletAddress,
    });

    if (!response.accounts || response.accounts.length === 0) {
      throw new Error('Lighter account not found for this wallet address');
    }

    const account = response.accounts[0]!;
    this.accountIndex = account.index;
    return account;
  }

  /**
   * Resolve account index (cached after first call)
   */
  private async getAccountIndex(): Promise<number> {
    if (this.accountIndex !== null) {
      return this.accountIndex;
    }

    const account = await this.fetchAccount();
    return account.index;
  }

  /**
   * Fetch trades with pagination
   */
  private async fetchAllTrades(accountId: number): Promise<LighterTrade[]> {
    const allTrades: LighterTrade[] = [];
    let cursor: string | undefined;
    const MAX_PAGES = 10;

    for (let page = 0; page < MAX_PAGES; page++) {
      const params: Record<string, string> = {
        account_index: accountId.toString(),
        type: 'trade',
      };
      if (cursor) {
        params.cursor = cursor;
      }

      const response = await this.makeRequest<LighterTradesResponse>('/api/v1/trades', params);
      if (response.trades && response.trades.length > 0) {
        allTrades.push(...response.trades);
      }

      if (!response.next_cursor || response.next_cursor === '' || response.trades.length === 0) {
        break;
      }

      cursor = response.next_cursor;
    }

    return allTrades;
  }

  /**
   * Generic GET request to Lighter API
   */
  private async makeRequest<T>(endpoint: string, params: Record<string, string>): Promise<T> {
    const url = new URL(`${this.apiUrl}${endpoint}`);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.append(key, value);
    }

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Lighter API error: ${response.status} - ${errorText}`);
    }

    return response.json() as Promise<T>;
  }

  // ========================================
  // Mapping helpers
  // ========================================

  /**
   * Map Lighter position to standard PositionData
   */
  private mapPosition(pos: LighterPosition): PositionData {
    const size = Number.parseFloat(pos.size) || 0;
    const isShort = pos.sign === -1;

    return {
      symbol: `${pos.symbol}/USD:USD`,
      side: isShort ? 'short' : 'long',
      size: Math.abs(size),
      entryPrice: Number.parseFloat(pos.avg_entry_price) || 0,
      markPrice: 0,
      unrealizedPnl: Number.parseFloat(pos.unrealized_pnl) || 0,
      liquidationPrice: pos.liquidation_price ? Number.parseFloat(pos.liquidation_price) : undefined,
    };
  }

  /**
   * Map Lighter trade to standard TradeData
   */
  private mapTrade(trade: LighterTrade, accountIndex: number): TradeData {
    const isTaker = trade.is_maker_ask
      ? trade.bid_account_id === accountIndex
      : trade.ask_account_id === accountIndex;
    const isBuyer = trade.bid_account_id === accountIndex;
    const fee = isTaker ? trade.taker_fee : trade.maker_fee;

    return {
      tradeId: trade.trade_id.toString(),
      symbol: `market_${trade.market_id}`,
      side: isBuyer ? 'buy' : 'sell',
      quantity: Math.abs(Number.parseFloat(trade.size)) || 0,
      price: Number.parseFloat(trade.price) || 0,
      fee: Math.abs(fee),
      feeCurrency: 'USDC',
      timestamp: new Date(trade.timestamp * 1000),
      realizedPnl: 0,
    };
  }

  /**
   * Map Lighter trade to ExecutedOrderData for snapshot aggregation
   */
  private mapExecutedOrder(trade: LighterTrade, accountIndex: number): ExecutedOrderData {
    const isTaker = trade.is_maker_ask
      ? trade.bid_account_id === accountIndex
      : trade.ask_account_id === accountIndex;
    const isBuyer = trade.bid_account_id === accountIndex;
    const fee = isTaker ? trade.taker_fee : trade.maker_fee;

    return {
      id: trade.trade_id.toString(),
      timestamp: trade.timestamp * 1000,
      symbol: `market_${trade.market_id}`,
      side: isBuyer ? 'buy' : 'sell',
      price: Number.parseFloat(trade.price) || 0,
      amount: Math.abs(Number.parseFloat(trade.size)) || 0,
      cost: Number.parseFloat(trade.usd_amount) || 0,
      fee: {
        cost: Math.abs(fee),
        currency: 'USDC',
      },
    };
  }
}
