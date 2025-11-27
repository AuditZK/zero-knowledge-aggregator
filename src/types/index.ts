export enum TradeType {
  BUY = 'buy',
  SELL = 'sell'
}

export enum TradeStatus {
  PENDING = 'pending',
  MATCHED = 'matched',
  PARTIALLY_MATCHED = 'partially_matched'
}

export interface User {
  id?: string; // Add optional id for compatibility
  uid: string;
  syncIntervalMinutes: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface Trade {
  id: string;
  userUid: string;
  symbol: string;
  type: TradeType;
  quantity: number;
  price: number;
  fees: number;
  timestamp: Date;
  exchange?: string;
  status: TradeStatus;
  matchedQuantity?: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface Position {
  id?: string;
  symbol: string;
  side: 'long' | 'short';
  quantity: number;
  entryPrice: number;
  currentPrice: number;
  unrealizedPnl: number;
  leverage?: number;
  timestamp?: Date;
}

export interface ReturnMetrics {
  volume: number;
  trades: number;
  returnPct: number;
  returnUsd: number;
  totalFees: number;
  realizedPnl: number; // PnL réalisé via matching
  unrealizedPnl?: number; // PnL non-réalisé (positions ouvertes)
  totalPnl?: number; // Total = realizedPnl + unrealizedPnl
  matches?: number; // Nombre de matches de la période
  openPositions?: number; // Nombre de positions ouvertes
  periodStart: string;
  periodEnd: string;
}

// Market-specific balance breakdown
export interface MarketBalanceBreakdown {
  totalEquityUsd: number;
  unrealizedPnl: number;
  realizedPnl?: number;
  availableBalance?: number;
  usedMargin?: number;
  positions?: number;
  // Trading activity metrics (per market type)
  volume?: number;          // Trading volume in USD
  orders?: number;          // Number of executed orders
  tradingFees?: number;     // Total trading fees (camelCase)
  fundingFees?: number;     // Funding fees - swap/perp only (camelCase)
  // snake_case aliases for gRPC mapping
  trading_fees?: number;    // Alias for tradingFees
  funding_fees?: number;    // Alias for fundingFees
  // IBKR format aliases (IbkrFlexConnector uses these)
  equity?: number;
  available_margin?: number;
}

export interface BreakdownByMarket {
  spot?: MarketBalanceBreakdown;
  swap?: MarketBalanceBreakdown;
  future?: MarketBalanceBreakdown;
  margin?: MarketBalanceBreakdown;
  option?: MarketBalanceBreakdown;
  options?: MarketBalanceBreakdown; // Alias for gRPC (uses plural)
  global?: MarketBalanceBreakdown;
}

export interface SnapshotData {
  id: string;
  userUid: string;
  timestamp: string; // Format: '2024-01-15T00:00:00.000Z' (DAILY snapshot timestamp at 00:00 UTC)
  exchange: string; // Exchange source (binance, bitget, ibkr, etc.)

  // Core equity tracking (CRITICAL for PnL calculation)
  totalEquity: number;        // Total account value (realized + unrealized positions)
  realizedBalance: number;    // Available cash/balance (no open positions)
  unrealizedPnL: number;      // Unrealized profit/loss from open positions

  // Cash flow tracking (REQUIRED for accurate PnL)
  // Daily PnL = (Equity_end - Equity_start) - Deposits + Withdrawals
  deposits: number;           // Cash deposited on this day
  withdrawals: number;        // Cash withdrawn on this day

  // Market breakdown (optional, for detailed analysis)
  breakdown_by_market?: BreakdownByMarket; // Market-specific breakdown (spot, swap, options)

  createdAt: Date;
  updatedAt: Date;
}

export interface CreateUserRequest {
  uid: string;
}

export interface CreateTradeRequest {
  userUid: string;
  symbol: string;
  type: TradeType;
  quantity: number;
  price: number;
  fees: number;
  timestamp?: Date;
  exchange?: string;
  exchangeTradeId?: string;
}

export interface GetReturnsQuery {
  startHour?: string; // Format: '2024-01-15T14:00:00.000Z'
  endHour?: string;   // Format: '2024-01-15T15:00:00.000Z'
  symbol?: string;
  aggregation?: 'snapshot' | 'daily' | 'weekly' | 'monthly';
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginationQuery {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface DatabaseConfig {
  url: string;
  ssl: boolean;
  maxConnections?: number;
  idleTimeoutMillis?: number;
}

export interface ServerConfig {
  port: number;
  nodeEnv: string;
  apiPrefix: string;
  corsOrigin: string | string[];
  jwtSecret: string;
  bcryptRounds: number;
  logLevel: string;
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  dataRetentionDays: number;
}

export interface TradeData {
  userUid: string;
  exchangeTradeId: string;
  exchange: string;
  symbol: string;
  type: 'buy' | 'sell';
  quantity: number;
  price: number;
  fees: number;
  timestamp: Date;
  orderId?: string;
}

export interface ExchangeConnection {
  id: string;
  userUid: string;
  exchange: string;
  label: string;
  encryptedApiKey: string;
  encryptedApiSecret: string;
  encryptedPassphrase?: string;
  credentialsHash?: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ExchangeCredentials {
  userUid: string;
  exchange: string;
  label: string;
  apiKey: string;
  apiSecret: string;
  passphrase?: string;
  isActive?: boolean;
  // IBKR specific fields
  host?: string;
  port?: number;
  clientId?: number;
}

export interface SyncStatus {
  id: string;
  userUid: string;
  exchange: string;
  lastSyncTime?: Date;
  status: 'pending' | 'syncing' | 'completed' | 'error';
  totalTrades: number;
  errorMessage?: string;
  createdAt: Date;
  updatedAt: Date;
}

// Logger metadata type (flexible for Express query params, etc.)
export type LogMetadata = {
  [key: string]: unknown;
};

// Database raw query result types
export interface DatabaseTableInfo {
  column_name: string;
  data_type: string;
  is_nullable: string;
  column_default: string | null;
}

export interface DatabaseMigrationInfo {
  table_name: string;
  column_count: number;
}

// Alpaca SDK types
export interface AlpacaPosition {
  symbol: string;
  qty: string;
  side: 'long' | 'short';
  market_value: string;
  cost_basis: string;
  unrealized_pl: string;
  unrealized_plpc: string;
  current_price: string;
  lastday_price: string;
  change_today: string;
  avg_entry_price?: string;
  asset_class?: string;
}

export interface AlpacaActivity {
  id: string;
  activity_type: string;
  transaction_time: string;
  type: string;
  price: string;
  qty: string;
  side: 'buy' | 'sell';
  symbol: string;
  leaves_qty: string;
  order_id: string;
  cum_qty: string;
  order_status: string;
  net_amount?: string;
}

export interface AlpacaAccount {
  id: string;
  account_number: string;
  status: string;
  currency: string;
  buying_power: string;
  regt_buying_power: string;
  daytrading_buying_power: string;
  cash: string;
  portfolio_value: string;
  pattern_day_trader: boolean;
  trading_blocked: boolean;
  transfers_blocked: boolean;
  account_blocked: boolean;
  created_at: string;
  trade_suspended_by_user: boolean;
  multiplier: string;
  shorting_enabled: boolean;
  equity: string;
  last_equity: string;
  long_market_value: string;
  short_market_value: string;
  initial_margin: string;
  maintenance_margin: string;
  last_maintenance_margin: string;
  sma: string;
  daytrade_count: number;
}

// CCXT position type
export interface CCXTPosition {
  info: Record<string, unknown>;
  symbol: string;
  timestamp: number;
  datetime: string;
  initialMargin: number;
  initialMarginPercentage: number;
  maintenanceMargin: number;
  maintenanceMarginPercentage: number;
  entryPrice: number;
  notional: number;
  leverage: number;
  unrealizedPnl: number;
  contracts: number;
  contractSize: number;
  marginRatio: number;
  liquidationPrice: number;
  markPrice: number;
  collateral: number;
  marginMode: string;
  side: 'long' | 'short';
  percentage: number;
  realizedPnl?: number;
}

// Extended connector interfaces with specific methods
export interface IConnectorWithMarketTypes {
  detectMarketTypes(): Promise<string[]>;
  getBalanceByMarket(marketType: string): Promise<unknown>;
}

export interface IConnectorWithBalanceBreakdown {
  getBalanceBreakdown(): Promise<{
    global?: MarketBalanceBreakdown;
    [marketType: string]: MarketBalanceBreakdown | undefined;
  }>;
}

export interface IConnectorWithBalance {
  getBalance(): Promise<{
    totalEquityUsd: number;
    unrealizedPnl: number;
    [key: string]: unknown;
  }>;
}