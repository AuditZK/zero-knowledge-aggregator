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

/** Hyperliquid API base URL */
const HYPERLIQUID_API_URL = 'https://api.hyperliquid.xyz';

/** API response types */
interface HyperliquidClearinghouseState {
  marginSummary: {
    accountValue: string;
    totalNtlPos: string;
    totalRawUsd: string;
    totalMarginUsed: string;
  };
  crossMarginSummary: {
    accountValue: string;
    totalNtlPos: string;
    totalRawUsd: string;
    totalMarginUsed: string;
  };
  withdrawable: string;
  assetPositions: HyperliquidPosition[];
}

interface HyperliquidPosition {
  position: {
    coin: string;
    entryPx: string | null;
    leverage: {
      type: string;
      value: number;
    };
    liquidationPx: string | null;
    marginUsed: string;
    positionValue: string;
    returnOnEquity: string;
    szi: string; // Signed size (negative = short)
    unrealizedPnl: string;
  };
  type: string;
}

interface HyperliquidSpotState {
  balances: HyperliquidSpotBalance[];
}

interface HyperliquidSpotBalance {
  coin: string;
  token: number;
  total: string;
  hold: string;
  entryNtl: string;
}

interface HyperliquidLedgerUpdate {
  time: number;
  hash: string;
  delta: {
    type: string; // 'deposit' | 'withdraw' | 'internalTransfer' | 'spotTransfer' | etc.
    usdc: string;
  };
}

interface HyperliquidFill {
  coin: string;
  px: string;
  sz: string;
  side: 'A' | 'B'; // A = buy, B = sell
  time: number;
  startPosition: string;
  dir: string;
  closedPnl: string;
  hash: string;
  oid: number;
  crossed: boolean;
  fee: string;
  tid: number;
  feeToken: string;
}

/**
 * Hyperliquid DEX Connector
 *
 * Connects to Hyperliquid's REST API for reading account data.
 * No private key required for read-only operations (balance, positions, trades).
 *
 * API Reference: https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api
 *
 * Credentials:
 * - apiKey: Wallet address (0x...)
 * - apiSecret: Private key (optional, only needed for trading)
 */
export class HyperliquidConnector extends CryptoExchangeConnector {
  private readonly walletAddress: string;
  private readonly apiUrl: string;

  constructor(credentials: ExchangeCredentials) {
    super(credentials);

    // Validate wallet address format
    if (!credentials.apiKey?.startsWith('0x')) {
      throw new Error('Hyperliquid requires a valid wallet address (0x...) as apiKey');
    }

    this.walletAddress = credentials.apiKey.toLowerCase();
    this.apiUrl = HYPERLIQUID_API_URL;

    this.logger.info('Hyperliquid connector initialized');
  }

  getExchangeName(): string {
    return 'hyperliquid';
  }

  /**
   * Get perpetuals account balance (clearinghouse state)
   */
  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      const state = await this.fetchClearinghouseState();

      const accountValue = Number.parseFloat(state.marginSummary.accountValue) || 0;
      const totalRawUsd = Number.parseFloat(state.marginSummary.totalRawUsd) || 0;
      const totalMarginUsed = Number.parseFloat(state.marginSummary.totalMarginUsed) || 0;
      const withdrawable = Number.parseFloat(state.withdrawable) || 0;

      return {
        balance: totalRawUsd,
        equity: accountValue,
        unrealizedPnl: accountValue - totalRawUsd,
        currency: this.defaultCurrency,
        marginUsed: totalMarginUsed,
        marginAvailable: withdrawable,
      };
    });
  }

  /**
   * Get current perpetual positions
   */
  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      const state = await this.fetchClearinghouseState();

      return state.assetPositions
        .filter(pos => {
          const size = Number.parseFloat(pos.position.szi);
          return size !== 0;
        })
        .map(pos => this.mapPosition(pos));
    });
  }

  /**
   * Get trade history (fills)
   * Note: Hyperliquid returns max 2000 most recent fills
   */
  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      const fills = await this.fetchUserFills();

      return fills
        .filter(fill => {
          const fillDate = new Date(fill.time);
          return this.isInDateRange(fillDate, startDate, endDate);
        })
        .map(fill => this.mapFill(fill));
    });
  }

  /**
   * Test connection by fetching clearinghouse state
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.fetchClearinghouseState();
      this.logger.info('Hyperliquid: Connection test successful');
      return true;
    } catch (error) {
      this.logger.error('Hyperliquid: Connection test failed', error);
      return false;
    }
  }

  /**
   * Detect available market types
   * Hyperliquid supports: perp (swap) and spot
   */
  async detectMarketTypes(): Promise<MarketType[]> {
    const markets: MarketType[] = ['swap']; // Perps always available

    // Check if user has spot activity
    try {
      const spotState = await this.fetchSpotState();
      if (spotState.balances && spotState.balances.length > 0) {
        markets.push('spot');
      }
    } catch {
      this.logger.debug('Spot market check failed, assuming perps only');
    }

    return markets;
  }

  /**
   * Get balance breakdown by market type
   */
  async getBalanceByMarket(marketType: MarketType): Promise<MarketBalanceData> {
    return this.withErrorHandling('getBalanceByMarket', async () => {
      if (marketType === 'spot') {
        return this.getSpotBalance();
      }

      // Default: perpetuals (swap)
      const state = await this.fetchClearinghouseState();
      const equity = Number.parseFloat(state.marginSummary.accountValue) || 0;
      const availableMargin = Number.parseFloat(state.withdrawable) || 0;
      const marginUsed = Number.parseFloat(state.marginSummary.totalMarginUsed) || 0;

      return { equity, available_margin: availableMargin, margin_used: marginUsed };
    });
  }

  /**
   * Get executed orders for a market type
   */
  async getExecutedOrders(marketType: MarketType, since: Date): Promise<ExecutedOrderData[]> {
    return this.withErrorHandling('getExecutedOrders', async () => {
      if (marketType === 'spot') {
        // Spot fills would need a separate endpoint if available
        this.logger.warn('Spot trade history not yet implemented for Hyperliquid');
        return [];
      }

      const fills = await this.fetchUserFillsByTime(since.getTime());

      return fills.map(fill => ({
        id: fill.tid.toString(),
        timestamp: fill.time,
        symbol: `${fill.coin}/USD:USD`,
        side: fill.side === 'A' ? 'buy' : 'sell' as 'buy' | 'sell',
        price: Number.parseFloat(fill.px) || 0,
        amount: Math.abs(Number.parseFloat(fill.sz)) || 0,
        cost: Math.abs(Number.parseFloat(fill.px) * Number.parseFloat(fill.sz)) || 0,
        fee: {
          cost: Math.abs(Number.parseFloat(fill.fee)) || 0,
          currency: fill.feeToken || 'USDC',
        },
      }));
    });
  }

  /**
   * Get deposits and withdrawals since a date
   * Hyperliquid uses USDC for all transfers (1:1 to USD)
   */
  async getCashflows(since: Date): Promise<{ deposits: number; withdrawals: number }> {
    return this.withErrorHandling('getCashflows', async () => {
      const ledgerUpdates = await this.postInfo<HyperliquidLedgerUpdate[]>({
        type: 'userNonFundingLedgerUpdates',
        user: this.walletAddress,
        startTime: since.getTime(),
      });

      let deposits = 0;
      let withdrawals = 0;

      for (const entry of ledgerUpdates) {
        const amount = Math.abs(Number.parseFloat(entry.delta.usdc) || 0);
        if (entry.delta.type === 'deposit') {
          deposits += amount;
        } else if (entry.delta.type === 'withdraw') {
          withdrawals += amount;
        }
      }

      if (deposits > 0 || withdrawals > 0) {
        this.logger.info(`Hyperliquid cashflows since ${since.toISOString()}: +${deposits.toFixed(2)} deposits, -${withdrawals.toFixed(2)} withdrawals`);
      }

      return { deposits, withdrawals };
    });
  }

  // ========================================
  // Private API methods
  // ========================================

  /**
   * Fetch perpetuals clearinghouse state
   */
  private async fetchClearinghouseState(): Promise<HyperliquidClearinghouseState> {
    return this.postInfo<HyperliquidClearinghouseState>({
      type: 'clearinghouseState',
      user: this.walletAddress,
    });
  }

  /**
   * Fetch spot clearinghouse state
   */
  private async fetchSpotState(): Promise<HyperliquidSpotState> {
    return this.postInfo<HyperliquidSpotState>({
      type: 'spotClearinghouseState',
      user: this.walletAddress,
    });
  }

  /**
   * Fetch user fills (trade history)
   */
  private async fetchUserFills(): Promise<HyperliquidFill[]> {
    return this.postInfo<HyperliquidFill[]>({
      type: 'userFills',
      user: this.walletAddress,
    });
  }

  /**
   * Fetch user fills by time range
   */
  private async fetchUserFillsByTime(startTime: number, endTime?: number): Promise<HyperliquidFill[]> {
    const request: Record<string, unknown> = {
      type: 'userFillsByTime',
      user: this.walletAddress,
      startTime,
    };

    if (endTime) {
      request.endTime = endTime;
    }

    return this.postInfo<HyperliquidFill[]>(request);
  }

  /**
   * Generic POST to /info endpoint
   */
  private async postInfo<T>(body: Record<string, unknown>): Promise<T> {
    const response = await fetch(`${this.apiUrl}/info`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Hyperliquid API error: ${response.status} - ${errorText}`);
    }

    return response.json() as Promise<T>;
  }

  // ========================================
  // Mapping helpers
  // ========================================

  /**
   * Map Hyperliquid position to standard PositionData
   */
  private mapPosition(hlPos: HyperliquidPosition): PositionData {
    const pos = hlPos.position;
    const size = Number.parseFloat(pos.szi) || 0;
    const isShort = size < 0;

    return {
      symbol: `${pos.coin}/USD:USD`,
      side: isShort ? 'short' : 'long',
      size: Math.abs(size),
      entryPrice: Number.parseFloat(pos.entryPx || '0') || 0,
      markPrice: 0, // Not directly available in clearinghouseState
      unrealizedPnl: Number.parseFloat(pos.unrealizedPnl) || 0,
      leverage: pos.leverage?.value || 1,
      liquidationPrice: pos.liquidationPx ? Number.parseFloat(pos.liquidationPx) : undefined,
    };
  }

  /**
   * Map Hyperliquid fill to standard TradeData
   */
  private mapFill(fill: HyperliquidFill): TradeData {
    return {
      tradeId: fill.tid.toString(),
      symbol: `${fill.coin}/USD:USD`,
      side: fill.side === 'A' ? 'buy' : 'sell',
      quantity: Math.abs(Number.parseFloat(fill.sz)) || 0,
      price: Number.parseFloat(fill.px) || 0,
      fee: Math.abs(Number.parseFloat(fill.fee)) || 0,
      feeCurrency: fill.feeToken || 'USDC',
      timestamp: new Date(fill.time),
      orderId: fill.oid.toString(),
      realizedPnl: Number.parseFloat(fill.closedPnl) || 0,
    };
  }

  /**
   * Get spot balance with USD conversion
   */
  private async getSpotBalance(): Promise<MarketBalanceData> {
    const spotState = await this.fetchSpotState();

    let totalEquity = 0;

    for (const balance of spotState.balances) {
      const total = Number.parseFloat(balance.total) || 0;
      if (total <= 0) continue;

      // USDC is the base currency on Hyperliquid
      if (balance.coin === 'USDC') {
        totalEquity += total;
      } else {
        // For other tokens, use entryNtl as approximate USD value
        // or fetch current price (not implemented for simplicity)
        const entryNotional = Number.parseFloat(balance.entryNtl) || 0;
        if (entryNotional > 0) {
          totalEquity += entryNotional;
        }
      }
    }

    return { equity: totalEquity, available_margin: 0 };
  }
}
