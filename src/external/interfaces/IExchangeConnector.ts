/**
 * Common interfaces for exchange connectors
 * All exchange implementations must conform to these interfaces
 */

/**
 * Balance and equity data
 */
export interface BalanceData {
  balance: number;
  equity: number;
  unrealizedPnl: number;
  currency: string;
  marginUsed?: number;
  marginAvailable?: number;
}

/**
 * Capital flow (deposit/withdrawal) data
 */
export interface CapitalFlowData {
  type: 'deposit' | 'withdrawal';
  amount: number;
  currency: string;
  timestamp: Date;
  txId: string;
  status: 'pending' | 'completed' | 'failed';
  fee?: number;
  network?: string;
  address?: string;
}

/**
 * Trade execution data
 */
export interface TradeData {
  tradeId: string;
  symbol: string;
  side: 'buy' | 'sell';
  quantity: number;
  price: number;
  fee: number;
  feeCurrency: string;
  timestamp: Date;
  orderId?: string;
  realizedPnl?: number;
}

/**
 * Position data
 */
export interface PositionData {
  symbol: string;
  side: 'long' | 'short';
  size: number;
  entryPrice: number;
  markPrice: number;
  unrealizedPnl: number;
  realizedPnl?: number;
  leverage?: number;
  liquidationPrice?: number;
}

/**
 * Supported features by exchange
 */
export type ExchangeFeature =
  | 'capital_flows'     // Deposits/withdrawals via API
  | 'positions'         // Position tracking
  | 'trades'            // Trade history
  | 'real_time'         // Real-time data
  | 'historical_data';  // Historical market data

/**
 * Common interface for all exchange connectors
 *
 * Design principles:
 * - All methods return normalized data structures
 * - Date ranges use Date objects (not timestamps)
 * - Errors are thrown, not returned
 * - Feature detection via supportsFeature()
 */
export interface IExchangeConnector {
  /**
   * Test connection to exchange
   * @returns true if connection successful
   */
  testConnection(): Promise<boolean>;

  /**
   * Get account balance and equity
   * @returns Balance data with equity and unrealized PnL
   */
  getBalance(): Promise<BalanceData>;

  /**
   * Get current open positions
   * @returns Array of open positions
   */
  getCurrentPositions(): Promise<PositionData[]>;

  /**
   * Get historical trades in date range
   * @param startDate Start date (inclusive)
   * @param endDate End date (inclusive)
   * @returns Array of trades
   */
  getTrades(startDate: Date, endDate: Date): Promise<TradeData[]>;

  /**
   * Get deposit history in date range
   * @param startDate Start date (inclusive)
   * @param endDate End date (inclusive)
   * @returns Array of deposits
   * @throws Error if capital_flows feature not supported
   */
  getDeposits(startDate: Date, endDate: Date): Promise<CapitalFlowData[]>;

  /**
   * Get withdrawal history in date range
   * @param startDate Start date (inclusive)
   * @param endDate End date (inclusive)
   * @returns Array of withdrawals
   * @throws Error if capital_flows feature not supported
   */
  getWithdrawals(startDate: Date, endDate: Date): Promise<CapitalFlowData[]>;

  /**
   * Get exchange name (lowercase)
   * @returns Exchange identifier (e.g., 'bitget', 'binance', 'ibkr')
   */
  getExchangeName(): string;

  /**
   * Check if exchange supports a feature
   * @param feature Feature to check
   * @returns true if feature is supported
   */
  supportsFeature(feature: ExchangeFeature): boolean;
}
