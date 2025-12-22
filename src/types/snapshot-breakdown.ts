/**
 * Spot market snapshot (no funding fees on spot)
 */
export interface SpotMarketSnapshot {
  equity: number;
  volume: number;
  orders: number;
  trading_fees: number;
}

/**
 * Derivatives market snapshot (swap, future, option - has funding fees)
 */
export interface DerivativesMarketSnapshot extends SpotMarketSnapshot {
  funding_fees: number;
}

/**
 * Generic market snapshot (for backward compatibility)
 */
export type MarketSnapshot = SpotMarketSnapshot | DerivativesMarketSnapshot;

/**
 * Global snapshot includes available_margin and funding_fees
 */
export interface GlobalSnapshot extends DerivativesMarketSnapshot {
  available_margin: number;
}

/**
 * Complete snapshot with breakdown by market type
 *
 * Structure:
 * {
 *   "timestamp": "2025-11-08T15:00:10",
 *   "breakdown_by_market": {
 *     "global": { equity, available_margin, volume, orders, trading_fees, funding_fees },
 *     "spot": { equity, volume, orders, trading_fees }, // NO funding_fees on spot
 *     "swap": { equity, volume, orders, trading_fees, funding_fees },
 *     ...
 *   }
 * }
 */
export interface SnapshotBreakdown {
  timestamp: string;
  breakdown_by_market: {
    global: GlobalSnapshot;
    [marketType: string]: MarketSnapshot | GlobalSnapshot; // spot, swap, option, margin, etc.
  };
}

/**
 * Data returned by exchange APIs for balance by market type
 */
export interface MarketBalanceData {
  equity: number;
  available_margin?: number;
}

/**
 * Executed trade data (from fetchMyTrades)
 *
 * Note: We use fetchMyTrades instead of fetchClosedOrders to capture
 * partial fills correctly. For example, a limit order that fills over
 * multiple days will generate multiple trades, allowing us to attribute
 * volume to the correct time periods.
 */
export interface ExecutedOrderData {
  id: string;
  timestamp: number;
  symbol: string;
  side: 'buy' | 'sell';
  price: number;
  amount: number;
  cost: number; // Volume = price × amount
  fee?: {
    cost: number;
    currency: string;
  };
}

/**
 * Funding fee data (from fetchFundingHistory)
 */
export interface FundingFeeData {
  timestamp: number;
  symbol: string;
  amount: number; // Positive = received, negative = paid
}

/**
 * Unified account exchanges (Bitget, OKX, Bybit)
 * These exchanges have future and swap sharing the same wallet
 */
export const UNIFIED_ACCOUNT_EXCHANGES = ['bitget', 'okx', 'bybit'];

/**
 * Check if exchange uses unified account
 */
export function isUnifiedAccountExchange(exchangeId: string): boolean {
  return UNIFIED_ACCOUNT_EXCHANGES.includes(exchangeId.toLowerCase());
}

/**
 * Earn/Staking market snapshot (no trading, only equity and rewards)
 */
export interface EarnMarketSnapshot {
  equity: number;
  rewards?: number; // APY rewards earned
}

/**
 * Market types supported by crypto exchanges
 */
export type MarketType = 'spot' | 'swap' | 'future' | 'options' | 'margin' | 'earn';

/**
 * Get filtered market types for unified account exchanges
 * On unified accounts (Bitget, OKX, Bybit), 'swap' contains both swap and future data
 * We filter out 'future' and 'margin' to avoid duplication
 */
export function getFilteredMarketTypes(
  exchangeId: string,
  detectedTypes: MarketType[]
): MarketType[] {
  if (isUnifiedAccountExchange(exchangeId)) {
    // Filter out 'future' and 'margin' to avoid duplication
    return detectedTypes.filter(t => !['future', 'margin'].includes(t));
  }
  return detectedTypes;
}
