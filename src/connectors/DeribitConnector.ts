import * as ccxt from 'ccxt';
import { CryptoExchangeConnector } from '../external/base/CryptoExchangeConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
} from '../external/interfaces/IExchangeConnector';
import { ExchangeCredentials } from '../types';
import { extractErrorMessage } from '../utils/secure-enclave-logger';
import {
  MarketBalanceData,
  ExecutedOrderData,
  FundingFeeData,
  MarketType,
} from '../types/snapshot-breakdown';

/** Deribit settlement currencies (each has its own sub-account). */
const DERIBIT_CURRENCIES = ['BTC', 'ETH', 'USDC', 'USDT'] as const;
type DeribitCurrency = (typeof DERIBIT_CURRENCIES)[number];

/** Stablecoins that are already 1:1 to USD. */
const STABLECOINS = new Set(['USDC', 'USDT', 'USD']);

/** Cache TTL for market types and prices. */
const MARKET_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const PRICE_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const SYMBOL_CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

/**
 * Deribit Exchange Connector
 *
 * Deribit is a major crypto derivatives exchange specializing in:
 * - BTC/ETH options (European-style)
 * - BTC/ETH perpetual swaps
 * - BTC/ETH futures (quarterly expiry)
 * - USDC-margined perpetuals
 *
 * Key differences from other CCXT exchanges:
 * - Settlement in BTC/ETH (not USDT) → requires USD price conversion
 * - Multi-currency accounts (BTC, ETH, USDC, USDT sub-accounts)
 * - Options as primary product (most exchanges only have futures/perps)
 * - No fetchFundingHistory in CCXT → use fetchFundingRateHistory + positions
 *
 * Credentials:
 * - apiKey: Deribit API key (from Account > API)
 * - apiSecret: Deribit API secret
 */
export class DeribitConnector extends CryptoExchangeConnector {
  private readonly exchange: ccxt.Exchange;

  /** Cached USD prices for BTC/ETH. */
  private readonly priceCache: Map<string, { price: number; expiry: number }> = new Map();

  /** Cached market types. */
  private cachedMarketTypes: MarketType[] | null = null;
  private marketTypesExpiry = 0;

  /** Cached active symbols by market type. */
  private readonly cachedSymbols: Map<string, { symbols: string[]; expiry: number }> = new Map();

  constructor(credentials: ExchangeCredentials) {
    super(credentials);

    if (!credentials.apiKey || !credentials.apiSecret) {
      throw new Error('Deribit requires apiKey and apiSecret');
    }

    this.exchange = new ccxt.deribit({
      apiKey: credentials.apiKey,
      secret: credentials.apiSecret,
      enableRateLimit: true,
    });

    this.logger.info('Deribit connector initialized');
  }

  getExchangeName(): string {
    return 'deribit';
  }

  /** Connected to production API (www.deribit.com) — always live. */
  async detectIsPaper(): Promise<boolean> {
    return false;
  }

  // ========================================
  // Core IExchangeConnector methods
  // ========================================

  async testConnection(): Promise<boolean> {
    try {
      await this.exchange.fetchBalance({ code: 'BTC' });
      this.logger.info('Deribit: Connection test successful');
      return true;
    } catch (error) {
      this.logger.error('Deribit: Connection test failed', error);
      return false;
    }
  }

  /**
   * Get total balance across all Deribit currency accounts, converted to USD.
   *
   * Deribit has separate sub-accounts per currency (BTC, ETH, USDC, USDT).
   * We fetch each and convert to USD using current index price.
   */
  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      let totalEquity = 0;
      let totalBalance = 0;
      let totalMarginUsed = 0;
      let totalMarginAvailable = 0;

      for (const currency of DERIBIT_CURRENCIES) {
        const { equity, balance, marginUsed, marginAvailable } =
          await this.fetchCurrencyBalance(currency);
        totalEquity += equity;
        totalBalance += balance;
        totalMarginUsed += marginUsed;
        totalMarginAvailable += marginAvailable;
      }

      return {
        balance: totalBalance,
        equity: totalEquity,
        unrealizedPnl: totalEquity - totalBalance,
        currency: 'USD',
        marginUsed: totalMarginUsed,
        marginAvailable: totalMarginAvailable,
      };
    });
  }

  /**
   * Get all open positions across all Deribit instruments.
   */
  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      const allPositions: PositionData[] = [];

      for (const currency of DERIBIT_CURRENCIES) {
        try {
          const positions = await this.exchange.fetchPositions(undefined, {
            currency,
          });

          for (const pos of positions) {
            if (!pos.contracts || pos.contracts === 0) continue;

            const usdMultiplier = await this.getUsdPrice(currency);

            allPositions.push({
              symbol: pos.symbol,
              side: pos.side as 'long' | 'short',
              size: Math.abs(pos.contracts || 0),
              entryPrice: pos.entryPrice || 0,
              markPrice: pos.markPrice || 0,
              unrealizedPnl: (pos.unrealizedPnl || 0) * usdMultiplier,
              realizedPnl: 0,
              leverage: pos.leverage || 1,
              liquidationPrice: pos.liquidationPrice,
            });
          }
        } catch (error) {
          this.logger.debug(`No positions for ${currency}: ${extractErrorMessage(error)}`);
        }
      }

      return allPositions;
    });
  }

  /**
   * Get trades across all Deribit instruments in a date range.
   */
  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      const since = this.dateToTimestamp(startDate);
      const allTrades: TradeData[] = [];

      for (const currency of DERIBIT_CURRENCIES) {
        const trades = await this.fetchTradesForCurrency(currency, since);

        for (const trade of trades) {
          const tradeDate = this.timestampToDate(trade.timestamp || 0);
          if (!this.isInDateRange(tradeDate, startDate, endDate)) continue;

          const usdMultiplier = STABLECOINS.has(currency) ? 1 : await this.getUsdPrice(currency);

          allTrades.push({
            tradeId: trade.id || `${trade.timestamp}`,
            symbol: trade.symbol || '',
            side: trade.side as 'buy' | 'sell',
            quantity: trade.amount || 0,
            price: trade.price || 0,
            fee: (trade.fee?.cost || 0) * usdMultiplier,
            feeCurrency: 'USD',
            timestamp: tradeDate,
            orderId: trade.order || '',
            realizedPnl: 0,
          });
        }
      }

      this.logger.info(`Fetched ${allTrades.length} trades from Deribit`);
      return allTrades;
    });
  }

  // ========================================
  // Extended methods for EquitySnapshotAggregator
  // ========================================

  /**
   * Detect available market types.
   * Deribit supports: swap (perpetuals), future (quarterly), options.
   */
  async detectMarketTypes(): Promise<MarketType[]> {
    return this.withErrorHandling('detectMarketTypes', async () => {
      const now = Date.now();
      if (this.cachedMarketTypes && this.marketTypesExpiry > now) {
        return this.cachedMarketTypes;
      }

      await this.exchange.loadMarkets();
      const types = new Set<MarketType>();

      for (const market of Object.values(this.exchange.markets)) {
        const info = market as Record<string, unknown>;
        if (info.swap) types.add('swap');
        if (info.future) types.add('future');
        if (info.option) types.add('options');
      }

      const detected = Array.from(types);
      this.cachedMarketTypes = detected;
      this.marketTypesExpiry = now + MARKET_CACHE_TTL_MS;

      this.logger.info(`Deribit market types: ${detected.join(', ')}`);
      return detected;
    });
  }

  /**
   * Get balance per market type, converted to USD.
   *
   * On Deribit, all market types share the same currency sub-accounts.
   * We attribute the full account equity to the queried market type
   * since positions across swap/future/options share the same collateral.
   */
  async getBalanceByMarket(marketType: MarketType): Promise<MarketBalanceData> {
    return this.withErrorHandling('getBalanceByMarket', async () => {
      // Deribit uses cross-margin: all products share the same collateral pool per currency.
      // We attribute equity based on positions in each market type.
      if (marketType === 'swap') {
        return this.getEquityForMarketType('swap');
      }
      if (marketType === 'future') {
        return this.getEquityForMarketType('future');
      }
      if (marketType === 'options') {
        return this.getEquityForMarketType('option');
      }

      return { equity: 0, available_margin: 0 };
    });
  }

  /**
   * Get executed orders for a market type since a date.
   */
  async getExecutedOrders(marketType: MarketType, since: Date): Promise<ExecutedOrderData[]> {
    return this.withErrorHandling('getExecutedOrders', async () => {
      const sinceTs = this.dateToTimestamp(since);
      const allOrders: ExecutedOrderData[] = [];

      for (const currency of DERIBIT_CURRENCIES) {
        const trades = await this.fetchTradesForCurrency(currency, sinceTs);
        const usdMultiplier = STABLECOINS.has(currency) ? 1 : await this.getUsdPrice(currency);

        for (const trade of trades) {
          if (!this.isMarketType(trade.symbol || '', marketType)) continue;

          allOrders.push({
            id: trade.id || `${trade.timestamp}`,
            timestamp: trade.timestamp || 0,
            symbol: trade.symbol || '',
            side: trade.side as 'buy' | 'sell',
            price: trade.price || 0,
            amount: trade.amount || 0,
            cost: (trade.cost || (trade.amount || 0) * (trade.price || 0)) * usdMultiplier,
            fee: trade.fee ? {
              cost: (trade.fee.cost || 0) * usdMultiplier,
              currency: 'USD',
            } : undefined,
          });
        }
      }

      this.logger.info(`Deribit ${marketType}: ${allOrders.length} executed orders`);
      return allOrders;
    });
  }

  /**
   * Funding fees are not directly available via CCXT for Deribit.
   * Deribit has fetchFundingRateHistory but not fetchFundingHistory (user-specific).
   * Return empty to avoid errors; funding is embedded in PnL on Deribit.
   */
  async getFundingFees(_symbols: string[], _since: Date): Promise<FundingFeeData[]> {
    this.logger.debug('Deribit: funding fees embedded in settlement PnL, returning empty');
    return [];
  }

  /**
   * Get deposits and withdrawals, converted to USD.
   */
  async getCashflows(since: Date): Promise<{ deposits: number; withdrawals: number }> {
    return this.withErrorHandling('getCashflows', async () => {
      const sinceTs = this.dateToTimestamp(since);

      const totalDeposits = this.exchange.has['fetchDeposits']
        ? await this.sumTransactions(sinceTs, 'fetchDeposits')
        : 0;

      const totalWithdrawals = this.exchange.has['fetchWithdrawals']
        ? await this.sumTransactions(sinceTs, 'fetchWithdrawals')
        : 0;

      if (totalDeposits > 0 || totalWithdrawals > 0) {
        this.logger.info(
          `Deribit cashflows since ${since.toISOString()}: ` +
          `+${totalDeposits.toFixed(2)} deposits, -${totalWithdrawals.toFixed(2)} withdrawals`
        );
      }

      return { deposits: totalDeposits, withdrawals: totalWithdrawals };
    });
  }

  /** Sum confirmed transactions (deposits or withdrawals) across all currencies, converted to USD. */
  private async sumTransactions(
    sinceTs: number,
    method: 'fetchDeposits' | 'fetchWithdrawals'
  ): Promise<number> {
    let total = 0;

    for (const currency of DERIBIT_CURRENCIES) {
      try {
        const transactions = await this.exchange[method](currency, sinceTs);
        const usdMultiplier = STABLECOINS.has(currency) ? 1 : await this.getUsdPrice(currency);

        for (const tx of transactions) {
          if (tx.status === 'ok' && tx.amount) {
            total += tx.amount * usdMultiplier;
          }
        }
      } catch (error) {
        this.logger.debug(`${method}(${currency}) failed: ${extractErrorMessage(error)}`);
      }
    }

    return total;
  }

  // ========================================
  // Private helpers
  // ========================================

  /**
   * Fetch balance for a single Deribit currency account and convert to USD.
   */
  private async fetchCurrencyBalance(currency: DeribitCurrency): Promise<{
    equity: number;
    balance: number;
    marginUsed: number;
    marginAvailable: number;
  }> {
    try {
      const response = await this.exchange.fetchBalance({ code: currency });
      const info = response.info as Record<string, unknown> | undefined;

      // Deribit returns: { equity, balance, available_withdrawal_funds, maintenance_margin, ... }
      const rawEquity = Number(info?.equity) || 0;
      const rawBalance = Number(info?.balance) || 0;
      const rawAvailable = Number(info?.available_withdrawal_funds) || 0;
      const rawMarginUsed = Number(info?.maintenance_margin) || 0;

      if (rawEquity === 0 && rawBalance === 0) {
        return { equity: 0, balance: 0, marginUsed: 0, marginAvailable: 0 };
      }

      const usdMultiplier = STABLECOINS.has(currency) ? 1 : await this.getUsdPrice(currency);

      return {
        equity: rawEquity * usdMultiplier,
        balance: rawBalance * usdMultiplier,
        marginUsed: rawMarginUsed * usdMultiplier,
        marginAvailable: rawAvailable * usdMultiplier,
      };
    } catch (error) {
      this.logger.debug(`No ${currency} account on Deribit: ${extractErrorMessage(error)}`);
      return { equity: 0, balance: 0, marginUsed: 0, marginAvailable: 0 };
    }
  }

  /**
   * Get USD price for a crypto currency (BTC, ETH).
   * Uses Deribit's index price via ticker, cached for 5 minutes.
   */
  private async getUsdPrice(currency: string): Promise<number> {
    if (STABLECOINS.has(currency)) return 1;

    const now = Date.now();
    const cached = this.priceCache.get(currency);
    if (cached && cached.expiry > now) {
      return cached.price;
    }

    try {
      // Use the perpetual contract to get current price
      const symbol = `${currency}/USD:${currency}`;
      const ticker = await this.exchange.fetchTicker(symbol);
      const price = ticker.last || ticker.close || 0;

      if (price > 0) {
        this.priceCache.set(currency, { price, expiry: now + PRICE_CACHE_TTL_MS });
        this.logger.debug(`${currency}/USD price: $${price.toFixed(2)}`);
        return price;
      }
    } catch (error) {
      this.logger.debug(`Failed to fetch ${currency} price: ${extractErrorMessage(error)}`);
    }

    // Fallback: try USD pair directly
    try {
      const ticker = await this.exchange.fetchTicker(`${currency}/USD`);
      const price = ticker.last || ticker.close || 0;
      if (price > 0) {
        this.priceCache.set(currency, { price, expiry: now + PRICE_CACHE_TTL_MS });
        return price;
      }
    } catch {
      // Price unavailable
    }

    this.logger.warn(`Could not determine USD price for ${currency}`);
    return 0;
  }

  /**
   * Fetch trades for a specific currency using CCXT fetchMyTrades.
   * Discovers active symbols from closed orders and positions.
   */
  private async fetchTradesForCurrency(currency: string, since: number): Promise<ccxt.Trade[]> {
    const symbols = await this.getActiveSymbols(currency, since);
    const allTrades: ccxt.Trade[] = [];

    for (const symbol of symbols) {
      try {
        const trades = await this.exchange.fetchMyTrades(symbol, since);
        if (trades.length > 0) {
          allTrades.push(...trades);
        }
      } catch {
        // Symbol might have no trades
      }
    }

    return allTrades;
  }

  /**
   * Discover active symbols for a currency from closed orders and positions.
   * Cached to reduce API calls.
   */
  private async getActiveSymbols(currency: string, since?: number): Promise<string[]> {
    const cacheKey = `${currency}:${since || 'all'}`;
    const now = Date.now();
    const cached = this.cachedSymbols.get(cacheKey);

    if (cached && cached.expiry > now) {
      return cached.symbols;
    }

    const symbols = new Set<string>();

    // From closed orders
    try {
      const closedOrders = await this.exchange.fetchClosedOrders(undefined, since, undefined, {
        currency,
      });
      for (const order of closedOrders) {
        if (order.symbol) symbols.add(order.symbol);
      }
    } catch {
      this.logger.debug(`fetchClosedOrders(${currency}) not available`);
    }

    // From positions
    try {
      const positions = await this.exchange.fetchPositions(undefined, { currency });
      for (const pos of positions) {
        if (pos.symbol && pos.contracts && pos.contracts !== 0) {
          symbols.add(pos.symbol);
        }
      }
    } catch {
      // No positions
    }

    const result = Array.from(symbols);
    this.cachedSymbols.set(cacheKey, { symbols: result, expiry: now + SYMBOL_CACHE_TTL_MS });
    this.logger.debug(`Deribit ${currency}: ${result.length} active symbols`);

    return result;
  }

  /**
   * Check if a symbol belongs to a specific market type.
   * Uses Deribit naming conventions:
   * - Perpetuals: BTC-PERPETUAL, ETH-PERPETUAL → swap
   * - Futures: BTC-28MAR25 (6-digit date) → future
   * - Options: BTC-28MAR25-80000-C → options
   */
  private isMarketType(symbol: string, marketType: MarketType): boolean {
    const upper = symbol.toUpperCase();

    if (marketType === 'options') {
      // Options have strike price and C/P suffix: BTC-28MAR25-80000-C
      return /\d+-[CP]/.test(upper);
    }
    if (marketType === 'swap') {
      return upper.includes('PERPETUAL') || upper.includes('PERP');
    }
    if (marketType === 'future') {
      // Futures have expiry date but NO strike/C/P: BTC-28MAR25
      return /[A-Z]+-\d{1,2}[A-Z]{3}\d{2}$/.test(upper);
    }
    return false;
  }

  /**
   * Calculate equity attributed to a specific market type.
   * On Deribit, collateral is shared, so we report total equity
   * and let the aggregator handle the breakdown.
   */
  private async getEquityForMarketType(
    ccxtType: 'swap' | 'future' | 'option'
  ): Promise<MarketBalanceData> {
    let totalEquity = 0;
    let totalMargin = 0;
    let totalMarginUsed = 0;

    for (const currency of DERIBIT_CURRENCIES) {
      try {
        const result = await this.getMarginForCurrency(currency, ccxtType);
        totalMarginUsed += result.marginUsed;

        if (result.hasPositions) {
          const { equity, marginAvailable } = await this.fetchCurrencyBalance(currency);
          totalEquity += equity;
          totalMargin += marginAvailable;
        }
      } catch (error) {
        this.logger.debug(`Error fetching ${currency} ${ccxtType} positions: ${extractErrorMessage(error)}`);
      }
    }

    return {
      equity: totalEquity,
      available_margin: totalMargin,
      margin_used: totalMarginUsed,
    };
  }

  /** Sum margin used for positions of a given kind in a single currency account. */
  private async getMarginForCurrency(
    currency: DeribitCurrency,
    ccxtType: string
  ): Promise<{ hasPositions: boolean; marginUsed: number }> {
    const positions = await this.exchange.fetchPositions(undefined, { currency });
    const usdMultiplier = STABLECOINS.has(currency) ? 1 : await this.getUsdPrice(currency);

    let hasPositions = false;
    let marginUsed = 0;

    for (const pos of positions) {
      if (!pos.contracts || pos.contracts === 0) continue;

      const info = pos.info as Record<string, unknown> | undefined;
      const rawKind = info?.kind;
      const kind = (typeof rawKind === 'string' ? rawKind : '').toLowerCase();
      if (kind !== ccxtType) continue;

      hasPositions = true;
      marginUsed += (pos.initialMargin || 0) * usdMultiplier;
    }

    return { hasPositions, marginUsed };
  }
}
