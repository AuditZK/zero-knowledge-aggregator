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
  getFilteredMarketTypes,
} from '../types/snapshot-breakdown';

/** Cache TTL in milliseconds. */
const MARKET_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const SYMBOL_CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

export class CcxtExchangeConnector extends CryptoExchangeConnector {
  private readonly exchange: ccxt.Exchange;
  private readonly exchangeName: string;

  /** Cached market types to avoid repeated loadMarkets() calls. */
  private cachedMarketTypes: MarketType[] | null = null;
  private marketTypesExpiry = 0;

  /** Cached active symbols by market type. */
  private readonly cachedSymbols: Map<string, { symbols: string[]; expiry: number }> = new Map();

  constructor(exchangeId: string, credentials: ExchangeCredentials) {
    super(credentials);
    this.exchangeName = exchangeId;
    const ExchangeClass = ccxt[exchangeId as keyof typeof ccxt] as typeof ccxt.Exchange;

    if (!ExchangeClass || typeof ExchangeClass !== 'function') {
      throw new Error(`Exchange '${exchangeId}' not supported by CCXT.`);
    }

    const exchangeConfig: Record<string, unknown> = {
      apiKey: credentials.apiKey,
      secret: credentials.apiSecret,
      password: credentials.passphrase,
      enableRateLimit: true,
      options: { defaultType: 'swap', recvWindow: 10000 },
    };

    // Route through proxy only for geo-restricted exchanges (default: binance only)
    const proxyUrl = process.env.EXCHANGE_HTTP_PROXY;
    if (proxyUrl) {
      const proxyExchanges = (process.env.PROXY_EXCHANGES || 'binance')
        .split(',')
        .map(e => e.trim().toLowerCase());
      if (proxyExchanges.includes(exchangeId.toLowerCase())) {
        exchangeConfig.httpProxy = proxyUrl;
      }
    }

    this.exchange = new ExchangeClass(exchangeConfig);

    this.logger.info(`CCXT connector initialized for ${exchangeId}`);
  }

  getExchangeName(): string {
    return this.exchangeName;
  }

  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      const balance = await this.exchange.fetchBalance();
      const extracted = this.extractSwapEquity(balance);
      return {
        balance: extracted.realizedBalance,
        equity: extracted.equity,
        unrealizedPnl: extracted.equity - extracted.realizedBalance,
        currency: this.defaultCurrency,
        marginUsed: extracted.marginUsed,
        marginAvailable: extracted.available,
      };
    });
  }

  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      const positions = await this.exchange.fetchPositions();
      return positions
        .filter(pos => pos.contracts && pos.contracts > 0)
        .map(pos => ({
          symbol: pos.symbol, side: pos.side as 'long' | 'short', size: Math.abs(pos.contracts || 0),
          entryPrice: pos.entryPrice || 0, markPrice: pos.markPrice || 0,
          unrealizedPnl: pos.unrealizedPnl || 0, realizedPnl: 0,
          leverage: pos.leverage || 1, liquidationPrice: pos.liquidationPrice,
          marginType: pos.marginMode,
        }));
    });
  }

  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      const since = this.dateToTimestamp(startDate);
      const marketTypes = await this.detectMarketTypes();
      const filteredTypes = getFilteredMarketTypes(this.exchangeName, marketTypes);

      this.logger.info(`Fetching trades from markets: ${filteredTypes.join(', ')}`);

      const tradeArrays: ccxt.Trade[][] = [];

      for (const marketType of filteredTypes) {
        const marketTrades = await this.fetchTradesForMarket(marketType, since);
        tradeArrays.push(marketTrades);
      }

      const allTrades = tradeArrays.flat();
      this.logger.info(`Total: ${allTrades.length} trades from ${filteredTypes.length} markets`);

      return this.mapAndFilterTrades(allTrades, startDate, endDate);
    });
  }

  /** Fetches trades for a specific market type. */
  private async fetchTradesForMarket(marketType: MarketType, since: number): Promise<ccxt.Trade[]> {
    const originalType = this.exchange.options['defaultType'];
    this.exchange.options['defaultType'] = marketType;

    try {
      const symbols = await this.getActiveSymbols(marketType, since);
      const symbolTradeArrays: ccxt.Trade[][] = [];

      for (const symbol of symbols) {
        try {
          const symbolTrades = await this.exchange.fetchMyTrades(symbol, since);
          if (symbolTrades.length > 0) {
            symbolTradeArrays.push(symbolTrades);
          }
        } catch {
          // Symbol might not have trades
        }
      }

      return symbolTradeArrays.flat();
    } finally {
      this.exchange.options['defaultType'] = originalType;
    }
  }

  /** Maps and filters trades to TradeData format. */
  private mapAndFilterTrades(trades: ccxt.Trade[], startDate: Date, endDate: Date): TradeData[] {
    const result: TradeData[] = [];

    for (const trade of trades) {
      const tradeDate = this.timestampToDate(trade.timestamp || 0);
      if (!this.isInDateRange(tradeDate, startDate, endDate)) {
        continue;
      }

      result.push({
        tradeId: trade.id || `${trade.timestamp}`,
        symbol: trade.symbol || '',
        side: trade.side as 'buy' | 'sell',
        quantity: trade.amount || 0,
        price: trade.price || 0,
        fee: trade.fee?.cost || 0,
        feeCurrency: trade.fee?.currency || this.defaultCurrency,
        timestamp: tradeDate,
        orderId: trade.order || '',
        realizedPnl: Number((trade.info as Record<string, unknown>)?.realizedPnl) || 0,
      });
    }

    return result;
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.exchange.fetchBalance();
      this.logger.info(`${this.exchangeName}: CCXT connection test successful`);
      return true;
    } catch (error) {
      this.logger.error(`${this.exchangeName}: CCXT connection test failed`, error);
      return false;
    }
  }

  async detectMarketTypes(): Promise<MarketType[]> {
    return this.withErrorHandling('detectMarketTypes', async () => {
      const now = Date.now();

      if (this.cachedMarketTypes && this.marketTypesExpiry > now) {
        return this.cachedMarketTypes;
      }

      await this.exchange.loadMarkets();
      const marketTypes = new Set<MarketType>();

      for (const market of Object.values(this.exchange.markets)) {
        const marketInfo = market as Record<string, unknown>;
        if (marketInfo.spot) { marketTypes.add('spot'); }
        if (marketInfo.swap) { marketTypes.add('swap'); }
        if (marketInfo.future) { marketTypes.add('future'); }
        if (marketInfo.option) { marketTypes.add('options'); }
        if (marketInfo.margin) { marketTypes.add('margin'); }
      }

      const detected = Array.from(marketTypes);
      this.cachedMarketTypes = detected;
      this.marketTypesExpiry = now + MARKET_CACHE_TTL_MS;

      this.logger.info(`Detected market types for ${this.exchangeName}: ${detected.join(', ')}`);
      return detected;
    });
  }

  async getBalanceByMarket(marketType: MarketType): Promise<MarketBalanceData> {
    return this.withErrorHandling('getBalanceByMarket', async () => {
      // For spot markets, calculate USD value of all assets (including altcoins)
      if (marketType === 'spot') {
        return this.getSpotBalanceWithUsdConversion();
      }

      // For derivatives (swap/future), get equity from raw API response
      this.exchange.options['defaultType'] = marketType;
      const balance = await this.exchange.fetchBalance();
      const extracted = this.extractSwapEquity(balance);

      return { equity: extracted.equity, available_margin: extracted.available, margin_used: extracted.marginUsed };
    });
  }

  /**
   * Extract full balance data from swap balance response.
   *
   * Exchange raw API formats:
   * - MEXC:   info.data[] → { currency, equity, cashBalance, availableBalance, positionMargin, unrealized }
   * - Bitget: info[]      → { marginCoin, accountEquity, available, unrealizedPL }
   * - Others: CCXT normalized balance[STABLECOIN] { free, total }
   */
  private extractSwapEquity(balance: Record<string, unknown>): {
    equity: number;
    realizedBalance: number;
    available: number;
    marginUsed: number;
  } {
    const info = balance.info as Record<string, unknown> | undefined;

    // MEXC: info = { data: [{ currency, equity, cashBalance, availableBalance, positionMargin }] }
    // Also handles nested info.data (CCXT may wrap response differently across versions)
    const mexcData = info?.data ?? (info as Record<string, unknown> | undefined);
    if (mexcData && Array.isArray(mexcData)) {
      // Sum ALL stablecoin equities (user may have USDT + USDC across sub-accounts)
      let totalEquity = 0;
      let totalRealized = 0;
      let totalAvailable = 0;
      let totalMarginUsed = 0;

      for (const asset of mexcData as Array<Record<string, unknown>>) {
        const currency = String(asset.currency || '');
        const equity = Number(asset.equity) || 0;
        if (this.STABLECOINS.includes(currency) && equity > 0) {
          totalEquity += equity;
          totalRealized += Number(asset.cashBalance) || 0;
          totalAvailable += Number(asset.availableBalance) || 0;
          totalMarginUsed += Number(asset.positionMargin) || 0;
        }
      }

      if (totalEquity > 0) {
        return { equity: totalEquity, realizedBalance: totalRealized, available: totalAvailable, marginUsed: totalMarginUsed };
      }

      // Log raw data for debugging when MEXC returns data but no stablecoin equity found
      const currencies = (mexcData as Array<Record<string, unknown>>)
        .filter((a) => Number(a.equity) > 0)
        .map((a) => `${a.currency}:${a.equity}`);
      if (currencies.length > 0) {
        this.logger.warn(`${this.exchangeName}: equity found in non-stablecoin currencies: [${currencies.join(', ')}]`);
      }
    }

    // Bitget classic: info = [{ marginCoin, accountEquity, available, unrealizedPL }]
    if (Array.isArray(info)) {
      for (const asset of info as Array<Record<string, unknown>>) {
        const coin = String(asset.marginCoin || '');
        if (this.STABLECOINS.includes(coin) && Number(asset.accountEquity) > 0) {
          const equity = Number(asset.accountEquity);
          const unrealized = Number(asset.unrealizedPL) || 0;
          return {
            equity,
            realizedBalance: equity - unrealized,
            available: Number(asset.available) || 0,
            marginUsed: Number(asset.locked) || 0,
          };
        }
      }
    }

    // Binance, OKX, Bybit, etc.: CCXT parseBalance maps equity → total correctly
    for (const coin of this.STABLECOINS) {
      const bal = balance[coin] as { free?: number; used?: number; total?: number } | undefined;
      if (bal?.total && bal.total > 0) {
        return {
          equity: bal.total,
          realizedBalance: bal.total,
          available: bal.free || 0,
          marginUsed: bal.used || 0,
        };
      }
    }

    // Debug: log available keys to understand response structure
    const balanceKeys = Object.keys(balance).filter(k => !this.BALANCE_META_KEYS.includes(k));
    const infoType = info ? (Array.isArray(info) ? 'array' : typeof info) : 'undefined';
    const infoDataType = info?.data ? (Array.isArray(info.data) ? `array[${(info.data as unknown[]).length}]` : typeof info.data) : 'missing';
    this.logger.warn(`${this.exchangeName}: no equity found in balance response`, {
      balanceKeys: balanceKeys.slice(0, 10),
      infoType,
      infoDataType,
    });
    return { equity: 0, realizedBalance: 0, available: 0, marginUsed: 0 };
  }

  /**
   * Get spot balance with USD conversion for all assets (stablecoins + altcoins)
   * Uses fetchTickers() to get all prices in a single API call
   */
  private async getSpotBalanceWithUsdConversion(): Promise<MarketBalanceData> {
    this.exchange.options['defaultType'] = 'spot';
    const balance = await this.exchange.fetchBalance({ type: 'spot' });

    // Collect altcoins that need price conversion
    const altcoins: { currency: string; total: number }[] = [];
    let totalUsdValue = 0;

    for (const [currency, value] of Object.entries(balance)) {
      if (this.BALANCE_META_KEYS.includes(currency)) continue;

      const holding = value as { total?: number | string };
      const total = Number(holding?.total) || 0;
      if (total <= 0) continue;

      if (this.STABLECOINS.includes(currency)) {
        totalUsdValue += total;
      } else {
        altcoins.push({ currency, total });
      }
    }

    // Fetch all prices in one call if we have altcoins
    if (altcoins.length > 0) {
      const prices = await this.fetchAltcoinPrices(altcoins.map(a => a.currency));

      for (const { currency, total } of altcoins) {
        const price = prices.get(currency) || 0;
        if (price > 0) {
          const usdValue = total * price;
          totalUsdValue += usdValue;
          this.logger.debug(`${currency}: ${total} @ $${price} = $${usdValue.toFixed(2)}`);
        }
      }
    }

    this.logger.info(`Spot wallet total: $${totalUsdValue.toFixed(2)} USD`);
    return { equity: totalUsdValue, available_margin: 0 };
  }

  /**
   * Fetch prices for multiple altcoins in a single API call using fetchTickers()
   */
  private async fetchAltcoinPrices(currencies: string[]): Promise<Map<string, number>> {
    const prices = new Map<string, number>();

    // Build symbols list (try USDT pairs first)
    const symbols = currencies.map(c => `${c}/USDT`);

    try {
      const tickers = await this.exchange.fetchTickers(symbols);

      for (const currency of currencies) {
        const symbol = `${currency}/USDT`;
        const ticker = tickers[symbol];
        if (ticker?.last) {
          prices.set(currency, Number(ticker.last));
        }
      }
    } catch {
      // Fallback: fetch individually for missing prices
      this.logger.debug('fetchTickers failed, falling back to individual fetches');
      for (const currency of currencies) {
        if (!prices.has(currency)) {
          const price = await this.fetchSinglePrice(currency);
          if (price > 0) prices.set(currency, price);
        }
      }
    }

    return prices;
  }

  /**
   * Fallback: fetch price for a single asset
   */
  private async fetchSinglePrice(currency: string): Promise<number> {
    for (const quote of ['USDT', 'USDC', 'USD']) {
      try {
        const ticker = await this.exchange.fetchTicker(`${currency}/${quote}`);
        if (ticker?.last) return Number(ticker.last);
      } catch {
        // Try next quote currency
      }
    }
    return 0;
  }

  async getExecutedOrders(marketType: MarketType, since: Date): Promise<ExecutedOrderData[]> {
    return this.withErrorHandling('getExecutedOrders', async () => {
      this.exchange.options['defaultType'] = marketType;
      const sinceTimestamp = this.dateToTimestamp(since);

      if (!this.exchange.has['fetchMyTrades']) {
        this.logger.warn(`${this.exchangeName} does not support fetchMyTrades`);
        return [];
      }

      const symbols = await this.getActiveSymbols(marketType, sinceTimestamp);
      if (symbols.length === 0) {
        this.logger.info(`No symbols traded in ${marketType} market`);
        return [];
      }

      this.logger.info(`Fetching trades for ${symbols.length} ${marketType} symbols`);

      const tradeArrays: ccxt.Trade[][] = [];

      for (const symbol of symbols) {
        try {
          const symbolTrades = await this.exchange.fetchMyTrades(symbol, sinceTimestamp);
          if (symbolTrades.length > 0) {
            tradeArrays.push(symbolTrades);
            this.logger.debug(`${symbol}: ${symbolTrades.length} trades`);
          }
        } catch {
          this.logger.debug(`${symbol}: no trades or error`);
        }
      }

      const allTrades = tradeArrays.flat();
      this.logger.info(`Total: ${allTrades.length} trades from ${marketType} market`);

      return this.mapTradesToExecutedOrders(allTrades);
    });
  }

  /**
   * Map CCXT trades to ExecutedOrderData
   * Each trade = one execution with its own timestamp (correct for daily volume distribution)
   */
  private mapTradesToExecutedOrders(trades: ccxt.Trade[]): ExecutedOrderData[] {
    return trades.map(trade => ({
      id: trade.id || `${trade.timestamp}`,
      timestamp: trade.timestamp || 0,
      symbol: trade.symbol || '',
      side: trade.side as 'buy' | 'sell',
      price: trade.price || 0,
      amount: trade.amount || 0,
      cost: trade.cost || (trade.amount || 0) * (trade.price || 0),
      fee: trade.fee ? {
        cost: trade.fee.cost || 0,
        currency: trade.fee.currency || this.defaultCurrency,
      } : undefined,
    }));
  }

  /**
   * Get symbols that were traded (from closed orders, positions, balances).
   * Results are cached for SYMBOL_CACHE_TTL_MS to reduce API calls.
   */
  private async getActiveSymbols(marketType: MarketType, since?: number): Promise<string[]> {
    const cacheKey = `${marketType}:${since || 'all'}`;
    const cached = this.cachedSymbols.get(cacheKey);
    const now = Date.now();

    if (cached && cached.expiry > now) {
      return cached.symbols;
    }

    const symbols = await this.discoverActiveSymbols(marketType, since);

    this.cachedSymbols.set(cacheKey, { symbols, expiry: now + SYMBOL_CACHE_TTL_MS });
    this.logger.info(`Discovered ${symbols.length} symbols for ${marketType}`);

    return symbols;
  }

  /** Discovers active symbols from closed orders, positions, and balances. */
  private async discoverActiveSymbols(marketType: MarketType, since?: number): Promise<string[]> {
    const symbols = new Set<string>();

    await this.addSymbolsFromClosedOrders(symbols, since);
    await this.addSymbolsFromPositions(symbols, marketType);
    await this.addSymbolsFromBalance(symbols, marketType);

    return Array.from(symbols);
  }

  private async addSymbolsFromClosedOrders(symbols: Set<string>, since?: number): Promise<void> {
    if (!this.exchange.has['fetchClosedOrders']) {
      return;
    }

    try {
      const closedOrders = await this.exchange.fetchClosedOrders(undefined, since);
      for (const order of closedOrders) {
        if (order.symbol) {
          symbols.add(order.symbol);
        }
      }
    } catch {
      this.logger.debug('fetchClosedOrders without symbol not supported');
    }
  }

  private async addSymbolsFromPositions(symbols: Set<string>, marketType: MarketType): Promise<void> {
    const isDerivativeMarket = marketType === 'swap' || marketType === 'future';
    if (!isDerivativeMarket || !this.exchange.has['fetchPositions']) {
      return;
    }

    try {
      const positions = await this.exchange.fetchPositions();
      for (const pos of positions) {
        if (pos.symbol) {
          symbols.add(pos.symbol);
        }
      }
    } catch {
      // Positions not available
    }
  }

  private async addSymbolsFromBalance(symbols: Set<string>, marketType: MarketType): Promise<void> {
    if (marketType !== 'spot') {
      return;
    }

    try {
      const balance = await this.exchange.fetchBalance();
      await this.exchange.loadMarkets();

      const totalBalances = balance.total as Record<string, number> | undefined;
      if (!totalBalances) {
        return;
      }

      const excludedAssets = new Set(['USDT', 'USD', 'USDC']);

      for (const [asset, total] of Object.entries(totalBalances)) {
        if (total > 0 && !excludedAssets.has(asset)) {
          const pair = `${asset}/USDT`;
          if (this.exchange.markets[pair]) {
            symbols.add(pair);
          }
        }
      }
    } catch {
      // Balance not available
    }
  }

  async getFundingFees(symbols: string[], since: Date): Promise<FundingFeeData[]> {
    return this.withErrorHandling('getFundingFees', async () => {
      if (!this.exchange.has['fetchFundingHistory']) {
        this.logger.warn(`${this.exchangeName} does not support fetchFundingHistory`);
        return [];
      }

      const sinceTimestamp = this.dateToTimestamp(since);
      const allFunding: FundingFeeData[] = [];

      for (const symbol of symbols) {
        try {
          const funding = await this.exchange.fetchFundingHistory(symbol, sinceTimestamp);
          for (const payment of funding) {
            allFunding.push({
              timestamp: payment.timestamp || 0,
              symbol: payment.symbol,
              amount: payment.amount || 0,
            });
          }
        } catch (error) {
          this.logger.warn(`Failed to fetch funding for ${symbol}:`, { error: extractErrorMessage(error) });
        }
      }

      return allFunding;
    });
  }

  /**
   * Get deposits and withdrawals since a date
   * Uses CCXT fetchDeposits/fetchWithdrawals (on-chain transfers)
   * Converts all currencies to USD (stablecoins 1:1, others via price lookup)
   */
  async getCashflows(since: Date): Promise<{ deposits: number; withdrawals: number }> {
    return this.withErrorHandling('getCashflows', async () => {
      const sinceTimestamp = this.dateToTimestamp(since);
      const allTransactions: Array<{ tx: ccxt.Transaction; direction: 'deposit' | 'withdrawal' }> = [];

      if (this.exchange.has['fetchDeposits']) {
        try {
          const deposits = await this.exchange.fetchDeposits(undefined, sinceTimestamp);
          for (const tx of deposits) {
            if (tx.status === 'ok') {
              allTransactions.push({ tx, direction: 'deposit' });
            }
          }
        } catch (error) {
          this.logger.debug('fetchDeposits not available', { error: extractErrorMessage(error) });
        }
      }

      if (this.exchange.has['fetchWithdrawals']) {
        try {
          const withdrawals = await this.exchange.fetchWithdrawals(undefined, sinceTimestamp);
          for (const tx of withdrawals) {
            if (tx.status === 'ok') {
              allTransactions.push({ tx, direction: 'withdrawal' });
            }
          }
        } catch (error) {
          this.logger.debug('fetchWithdrawals not available', { error: extractErrorMessage(error) });
        }
      }

      // Collect non-stablecoin currencies that need price conversion
      const altcoinCurrencies = new Set<string>();
      for (const { tx } of allTransactions) {
        const currency = tx.currency || '';
        if (currency && !this.STABLECOINS.includes(currency)) {
          altcoinCurrencies.add(currency);
        }
      }

      // Fetch prices for all non-stablecoin currencies in one batch
      const prices = altcoinCurrencies.size > 0
        ? await this.fetchAltcoinPrices(Array.from(altcoinCurrencies))
        : new Map<string, number>();

      let totalDeposits = 0;
      let totalWithdrawals = 0;

      for (const { tx, direction } of allTransactions) {
        const usdValue = this.transactionToUsd(tx, prices);
        if (usdValue > 0) {
          if (direction === 'deposit') {
            totalDeposits += usdValue;
          } else {
            totalWithdrawals += usdValue;
          }
        }
      }

      if (totalDeposits > 0 || totalWithdrawals > 0) {
        this.logger.info(`Cashflows since ${since.toISOString()}: +${totalDeposits.toFixed(2)} deposits, -${totalWithdrawals.toFixed(2)} withdrawals`);
      }

      return { deposits: totalDeposits, withdrawals: totalWithdrawals };
    });
  }

  /**
   * Convert a CCXT Transaction to USD value
   * Stablecoins: 1:1, others: use price lookup from pre-fetched prices map
   */
  private transactionToUsd(tx: ccxt.Transaction, prices: Map<string, number>): number {
    const amount = tx.amount || 0;
    if (amount <= 0) return 0;

    const currency = tx.currency || '';

    if (this.STABLECOINS.includes(currency)) {
      return amount;
    }

    const price = prices.get(currency);
    if (price && price > 0) {
      const usdValue = amount * price;
      this.logger.debug(`Converted cashflow: ${amount} ${currency} @ $${price} = $${usdValue.toFixed(2)}`);
      return usdValue;
    }

    this.logger.warn(`Non-stablecoin cashflow: no price found for ${amount} ${currency}, skipping`);
    return 0;
  }

  /**
   * Get balance from Earn/Staking products (flexible savings, staking, etc.)
   * Supported exchanges: Binance, Bitget, OKX, Bybit
   */
  async getEarnBalance(): Promise<MarketBalanceData> {
    return this.withErrorHandling('getEarnBalance', async () => {
      // Try standard CCXT earn methods first
      const standardEquity = await this.tryStandardEarnMethods();
      if (standardEquity > 0) {
        return { equity: standardEquity, available_margin: 0 };
      }

      // Try exchange-specific methods
      const specificEquity = await this.tryExchangeSpecificEarn();
      this.logger.info(`Total earn balance: ${specificEquity.toFixed(2)} USD`);
      return { equity: specificEquity, available_margin: 0 };
    });
  }

  private async tryStandardEarnMethods(): Promise<number> {
    const earnTypes = ['earn', 'savings', 'funding'];

    for (const earnType of earnTypes) {
      const equity = await this.tryEarnType(earnType);
      if (equity > 0) return equity;
    }

    return 0;
  }

  private async tryEarnType(earnType: string): Promise<number> {
    try {
      const balance = await this.exchange.fetchBalance({ type: earnType });
      const equity = this.sumStablecoinBalances(balance);

      if (equity > 0) {
        this.logger.info(`Earn balance (${earnType}): ${equity.toFixed(2)} USD`);
      }
      return equity;
    } catch (error) {
      this.logger.debug(`${earnType} balance not available: ${extractErrorMessage(error)}`);
      return 0;
    }
  }

  private readonly STABLECOINS = ['USDT', 'USDC', 'USD', 'BUSD', 'DAI'];
  private readonly BALANCE_META_KEYS = ['info', 'free', 'used', 'total', 'debt', 'timestamp', 'datetime'];

  private sumStablecoinBalances(balance: Record<string, unknown>): number {
    let total = 0;

    for (const [currency, value] of Object.entries(balance)) {
      if (this.BALANCE_META_KEYS.includes(currency)) continue;
      if (!this.STABLECOINS.includes(currency)) continue;

      const holding = value as { total?: number | string };
      if (holding?.total && Number(holding.total) > 0) {
        total += Number(holding.total) || 0;
      }
    }

    return total;
  }

  private async tryExchangeSpecificEarn(): Promise<number> {
    if (this.exchangeName.toLowerCase() !== 'binance') {
      return 0;
    }

    return this.tryBinanceSimpleEarn();
  }

  private async tryBinanceSimpleEarn(): Promise<number> {
    try {
      const earnProducts = await (this.exchange as any).sapiGetSimpleEarnFlexiblePosition();
      if (!earnProducts?.rows) return 0;

      return earnProducts.rows
        .filter((p: { asset: string }) => ['USDT', 'USDC', 'BUSD'].includes(p.asset))
        .reduce((sum: number, p: { totalAmount?: string }) => sum + Number.parseFloat(p.totalAmount || '0'), 0);
    } catch {
      this.logger.debug('Binance Simple Earn API not available');
      return 0;
    }
  }

  // ========================================
  // KYC Level Detection
  // ========================================

  /**
   * Detect if this is a paper/testnet account.
   * CCXT connectors always connect to production API — if auth succeeds, it's live.
   */
  async detectIsPaper(): Promise<boolean> {
    return false;
  }

  /** Exchanges that expose KYC verification level via API. */
  private static readonly KYC_SUPPORTED_EXCHANGES = ['bybit', 'okx', 'kucoin'] as const;

  /**
   * Fetch KYC verification level from the exchange API.
   * Only supported on: Bybit, OKX, KuCoin.
   *
   * @returns Normalized KYC level ("none" | "basic" | "intermediate" | "advanced") or null if unsupported
   */
  async fetchKycLevel(): Promise<string | null> {
    const exchange = this.exchangeName.toLowerCase();
    if (!CcxtExchangeConnector.KYC_SUPPORTED_EXCHANGES.includes(exchange as 'bybit' | 'okx' | 'kucoin')) {
      return null;
    }

    try {
      switch (exchange) {
        case 'bybit':
          return await this.fetchBybitKycLevel();
        case 'okx':
          return await this.fetchOkxKycLevel();
        case 'kucoin':
          return await this.fetchKucoinKycLevel();
        default:
          return null;
      }
    } catch (error) {
      this.logger.debug(`KYC level fetch failed for ${exchange}: ${extractErrorMessage(error)}`);
      return null;
    }
  }

  private async fetchBybitKycLevel(): Promise<string> {
    const response = await (this.exchange as any).privateGetV5UserQueryApi();
    const kycLevel = String(response?.result?.kycLevel || '');

    const BYBIT_KYC_MAP: Record<string, string> = {
      'LEVEL_DEFAULT': 'none',
      'LEVEL_1': 'basic',
      'LEVEL_2': 'advanced',
    };

    const normalized = BYBIT_KYC_MAP[kycLevel] || 'none';
    this.logger.info(`Bybit KYC level: ${kycLevel} → ${normalized}`);
    return normalized;
  }

  private async fetchOkxKycLevel(): Promise<string> {
    const response = await (this.exchange as any).privateGetAccountConfig();
    const data = Array.isArray(response?.data) ? response.data[0] : null;
    const kycLv = String(data?.kycLv || '0');

    const OKX_KYC_MAP: Record<string, string> = {
      '0': 'none',
      '1': 'basic',
      '2': 'intermediate',
      '3': 'advanced',
    };

    const normalized = OKX_KYC_MAP[kycLv] || 'none';
    this.logger.info(`OKX KYC level: ${kycLv} → ${normalized}`);
    return normalized;
  }

  private async fetchKucoinKycLevel(): Promise<string> {
    const response = await (this.exchange as any).privateGetUserApiKey();
    const kycStatus = Number(response?.data?.kycStatus ?? 0);

    const KUCOIN_KYC_MAP: Record<number, string> = {
      0: 'none',
      1: 'basic',
      2: 'advanced',
    };

    const normalized = KUCOIN_KYC_MAP[kycStatus] || 'none';
    this.logger.info(`KuCoin KYC level: ${kycStatus} → ${normalized}`);
    return normalized;
  }
}
