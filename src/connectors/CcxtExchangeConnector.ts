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
  isUnifiedAccountExchange,
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

    this.exchange = new ExchangeClass({
      apiKey: credentials.apiKey,
      secret: credentials.apiSecret,
      password: credentials.passphrase,
      enableRateLimit: true,
      options: { defaultType: 'future', recvWindow: 10000 },
    });

    this.logger.info(`CCXT connector initialized for ${exchangeId}`);
  }

  getExchangeName(): string {
    return this.exchangeName;
  }

  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      const balance = await this.exchange.fetchBalance();
      const usdtBalance = balance['USDT'] || balance['USD'] || balance.total;

      if (!usdtBalance) {
        this.logger.warn('No USDT/USD balance found, returning zero balance');
        return this.createBalanceData(0, 0, this.defaultCurrency);
      }

      return this.createBalanceData(usdtBalance.free || 0, usdtBalance.total || 0, this.defaultCurrency);
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
      if (isUnifiedAccountExchange(this.exchangeName)) {
        return this.getBalanceForUnifiedAccount(marketType);
      }

      this.exchange.options['defaultType'] = marketType;
      const balance = await this.exchange.fetchBalance();
      const usdtBalance = balance['USDT'] || balance['USD'] || balance['USDC'];

      if (!usdtBalance) {return { equity: 0, available_margin: 0 };}

      return { equity: usdtBalance.total || 0, available_margin: usdtBalance.free || 0 };
    });
  }

  private async getBalanceForUnifiedAccount(marketType: MarketType): Promise<MarketBalanceData> {
    if (marketType === 'spot') {
      this.exchange.options['defaultType'] = 'spot';
      const balance = await this.exchange.fetchBalance({ type: 'spot' });

      let spotEquity = 0;
      for (const [currency, value] of Object.entries(balance)) {
        if (['info', 'free', 'used', 'total', 'debt', 'timestamp', 'datetime'].includes(currency)) {continue;}
        const holding = value as any;
        if (holding?.total && Number(holding.total) > 0) {
          spotEquity += Number(holding.total) || 0;
        }
      }

      this.logger.info(`Spot wallet equity: ${spotEquity.toFixed(2)} USDT`);
      return { equity: spotEquity, available_margin: 0 };

    } else if (marketType === 'swap' || marketType === 'future') {
      this.exchange.options['defaultType'] = 'swap';
      const balance = await this.exchange.fetchBalance();
      const usdtBalance = balance['USDT'] || balance['USD'] || balance['USDC'];

      if (!usdtBalance) {
        this.logger.warn(`No USDT balance found in swap/unified account for ${this.exchangeName}`);
        return { equity: 0, available_margin: 0 };
      }

      const equity = usdtBalance.total || 0;
      const availableMargin = usdtBalance.free || 0;
      this.logger.info(`SWAP/Unified account equity: ${equity.toFixed(2)} USDT, margin: ${availableMargin.toFixed(2)} USDT`);

      return { equity, available_margin: availableMargin };
    } else {
      return { equity: 0, available_margin: 0 };
    }
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
   * Get balance from Earn/Staking products (flexible savings, staking, etc.)
   * Supported exchanges: Binance, Bitget, OKX, Bybit
   */
  async getEarnBalance(): Promise<MarketBalanceData> {
    return this.withErrorHandling('getEarnBalance', async () => {
      let earnEquity = 0;

      // Try different CCXT earn methods depending on exchange support
      // Method 1: fetchBalance with type 'earn' or 'savings'
      const earnTypes = ['earn', 'savings', 'funding'];

      for (const earnType of earnTypes) {
        try {
          const balance = await this.exchange.fetchBalance({ type: earnType });

          for (const [currency, value] of Object.entries(balance)) {
            if (['info', 'free', 'used', 'total', 'debt', 'timestamp', 'datetime'].includes(currency)) {continue;}
            const holding = value as any;
            if (holding?.total && Number(holding.total) > 0) {
              // For stablecoins, use direct value; for other assets, we'd need price conversion
              if (['USDT', 'USDC', 'USD', 'BUSD', 'DAI'].includes(currency)) {
                earnEquity += Number(holding.total) || 0;
              }
            }
          }

          if (earnEquity > 0) {
            this.logger.info(`Earn balance (${earnType}): ${earnEquity.toFixed(2)} USD`);
            return { equity: earnEquity, available_margin: 0 };
          }
        } catch (error) {
          this.logger.debug(`${earnType} balance not available: ${extractErrorMessage(error)}`);
        }
      }

      // Method 2: Try Binance-specific Simple Earn API
      if (this.exchangeName.toLowerCase() === 'binance') {
        try {
          // Binance Simple Earn - Flexible Products
          const earnProducts = await (this.exchange as any).sapiGetSimpleEarnFlexiblePosition();
          if (earnProducts?.rows) {
            for (const product of earnProducts.rows) {
              if (['USDT', 'USDC', 'BUSD'].includes(product.asset)) {
                earnEquity += parseFloat(product.totalAmount || 0);
              }
            }
          }
        } catch {
          this.logger.debug('Binance Simple Earn API not available');
        }
      }

      this.logger.info(`Total earn balance: ${earnEquity.toFixed(2)} USD`);
      return { equity: earnEquity, available_margin: 0 };
    });
  }
}
