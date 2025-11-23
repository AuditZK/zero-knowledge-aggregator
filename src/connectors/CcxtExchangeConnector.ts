import * as ccxt from 'ccxt';
import { CryptoExchangeConnector } from '../external/base/CryptoExchangeConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
  CapitalFlowData,
} from '../external/interfaces/IExchangeConnector';
import { ExchangeCredentials } from '../types';
import {
  MarketBalanceData,
  ExecutedOrderData,
  FundingFeeData,
  MarketType,
  isUnifiedAccountExchange,
  getFilteredMarketTypes,
} from '../types/snapshot-breakdown';

/**
 * CCXT-based Cryptocurrency Exchange Connector
 *
 * Unified connector that supports 100+ crypto exchanges via CCXT library.
 *
 * Supported exchanges (perpetuals/futures):
 * - Binance Futures (binanceusdm)
 * - Bitget Futures (bitget)
 * - MEXC Futures (mexc)
 * - OKX Futures (okx)
 * - Bybit Futures (bybit)
 * - And 100+ more...
 *
 * Benefits:
 * - Single implementation for all crypto exchanges
 * - CCXT handles API differences and rate limiting
 * - Community-maintained (regular updates)
 * - Retry logic and error handling built-in
 *
 * @example
 * // Binance Perpetuals
 * const binance = new CcxtExchangeConnector('binanceusdm', credentials);
 *
 * // Bitget Futures
 * const bitget = new CcxtExchangeConnector('bitget', credentials);
 *
 * // MEXC Futures
 * const mexc = new CcxtExchangeConnector('mexc', credentials);
 */
export class CcxtExchangeConnector extends CryptoExchangeConnector {
  private exchange: ccxt.Exchange;
  private exchangeName: string;

  /**
   * @param exchangeId - CCXT exchange ID (e.g., 'binanceusdm', 'bitget', 'mexc')
   * @param credentials - API credentials
   */
  constructor(exchangeId: string, credentials: ExchangeCredentials) {
    super(credentials);

    this.exchangeName = exchangeId;

    // Create CCXT exchange instance
    // CCXT will throw an error if the exchange is not supported
    const ExchangeClass = ccxt[exchangeId as keyof typeof ccxt] as typeof ccxt.Exchange;

    if (!ExchangeClass || typeof ExchangeClass !== 'function') {
      throw new Error(
        `Exchange '${exchangeId}' not supported by CCXT. ` +
        `Please check https://github.com/ccxt/ccxt#supported-cryptocurrency-exchange-markets for supported exchanges.`
      );
    }

    this.exchange = new ExchangeClass({
      apiKey: credentials.apiKey,
      secret: credentials.apiSecret,
      password: credentials.passphrase, // For exchanges that require it (e.g., Bitget)
      enableRateLimit: true, // Built-in rate limiting
      options: {
        defaultType: 'future', // Use futures/perpetuals by default
        recvWindow: 10000,
      },
    });

    this.logger.info(`CCXT connector initialized for ${exchangeId}`);
  }

  getExchangeName(): string {
    return this.exchangeName;
  }

  // ========================================
  // Required implementations
  // ========================================

  async getBalance(): Promise<BalanceData> {
    return this.withErrorHandling('getBalance', async () => {
      const balance = await this.exchange.fetchBalance();

      // For futures accounts, CCXT returns balance under 'USDT' or 'USD'
      const usdtBalance = balance['USDT'] || balance['USD'] || balance.total;

      if (!usdtBalance) {
        this.logger.warn('No USDT/USD balance found, returning zero balance');
        return this.createBalanceData(0, 0, this.defaultCurrency);
      }

      // CCXT structure: { free, used, total }
      const free = usdtBalance.free || 0;
      const total = usdtBalance.total || 0;

      return this.createBalanceData(free, total, this.defaultCurrency);
    });
  }

  async getCurrentPositions(): Promise<PositionData[]> {
    return this.withErrorHandling('getCurrentPositions', async () => {
      const positions = await this.exchange.fetchPositions();

      // Filter out closed positions (contracts = 0)
      return positions
        .filter(pos => pos.contracts && pos.contracts > 0)
        .map(pos => ({
          symbol: pos.symbol,
          side: pos.side as 'long' | 'short',
          size: Math.abs(pos.contracts || 0),
          entryPrice: pos.entryPrice || 0,
          markPrice: pos.markPrice || 0,
          unrealizedPnl: pos.unrealizedPnl || 0,
          realizedPnl: 0, // Not always available in CCXT
          leverage: pos.leverage || 1,
          liquidationPrice: pos.liquidationPrice,
          marginType: pos.marginMode,
        }));
    });
  }

  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    return this.withErrorHandling('getTrades', async () => {
      const since = this.dateToTimestamp(startDate);
      const endTimestamp = this.dateToTimestamp(endDate);

      // NEW: Detect all market types and fetch trades from ALL markets (spot, swap, future, etc.)
      // This ensures we capture trading activity across all market types, not just perpetuals
      const marketTypes = await this.detectMarketTypes();
      const filteredTypes = getFilteredMarketTypes(this.exchangeName, marketTypes);

      this.logger.info(`Fetching trades from all markets: ${filteredTypes.join(', ')}`);

      let allTrades: ccxt.Trade[] = [];

      // Fetch trades for each market type
      for (const marketType of filteredTypes) {
        try {
          // Temporarily change defaultType for this market
          const originalType = this.exchange.options['defaultType'];
          this.exchange.options['defaultType'] = marketType;

          if (this.exchange.has['fetchMyTrades']) {
            try {
              const marketTrades = await this.exchange.fetchMyTrades(
                undefined, // all symbols
                since,
                undefined, // no limit
                { endTime: endTimestamp }
              );

              if (marketTrades.length > 0) {
                allTrades.push(...marketTrades);
                this.logger.info(`Fetched ${marketTrades.length} trades from ${marketType} market`);
              }
            } catch (error) {
              this.logger.warn(`Failed to fetch ${marketType} trades:`, error);
              // Continue with other markets
            }
          }

          // Restore original type
          this.exchange.options['defaultType'] = originalType;
        } catch (error) {
          this.logger.error(`Error processing ${marketType} market:`, error);
        }
      }

      this.logger.info(`Total trades fetched: ${allTrades.length} from ${filteredTypes.length} markets`);

      // Filter by date range and map to our format
      return allTrades
        .filter(trade => {
          const tradeDate = this.timestampToDate(trade.timestamp || 0);
          return this.isInDateRange(tradeDate, startDate, endDate);
        })
        .map(trade => ({
          tradeId: trade.id || `${trade.timestamp}`,
          symbol: trade.symbol,
          side: trade.side as 'buy' | 'sell',
          quantity: trade.amount || 0,
          price: trade.price || 0,
          fee: trade.fee?.cost || 0,
          feeCurrency: trade.fee?.currency || this.defaultCurrency,
          timestamp: this.timestampToDate(trade.timestamp || 0),
          orderId: trade.order || '',
          realizedPnl: (trade.info as any)?.realizedPnl || 0,
        }));
    });
  }

  // ========================================
  // Capital flows implementation
  // ========================================

  protected async fetchDeposits(startDate: Date, endDate: Date): Promise<CapitalFlowData[]> {
    return this.withErrorHandling('fetchDeposits', async () => {
      if (!this.exchange.has['fetchDeposits']) {
        this.logger.warn(`${this.exchangeName} does not support fetchDeposits`);
        return [];
      }

      const since = this.dateToTimestamp(startDate);
      const deposits = await this.exchange.fetchDeposits(undefined, since);

      return deposits
        .filter(deposit => {
          const depositDate = this.timestampToDate(deposit.timestamp || 0);
          return this.isInDateRange(depositDate, startDate, endDate);
        })
        .map(deposit => ({
          type: 'deposit' as const,
          amount: deposit.amount || 0,
          currency: deposit.currency,
          timestamp: this.timestampToDate(deposit.timestamp || 0),
          txId: deposit.txid || deposit.id || '',
          status: this.mapDepositStatus(deposit.status),
          address: deposit.address,
          network: deposit.network,
        }));
    });
  }

  protected async fetchWithdrawals(startDate: Date, endDate: Date): Promise<CapitalFlowData[]> {
    return this.withErrorHandling('fetchWithdrawals', async () => {
      if (!this.exchange.has['fetchWithdrawals']) {
        this.logger.warn(`${this.exchangeName} does not support fetchWithdrawals`);
        return [];
      }

      const since = this.dateToTimestamp(startDate);
      const withdrawals = await this.exchange.fetchWithdrawals(undefined, since);

      return withdrawals
        .filter(withdrawal => {
          const withdrawalDate = this.timestampToDate(withdrawal.timestamp || 0);
          return this.isInDateRange(withdrawalDate, startDate, endDate);
        })
        .map(withdrawal => ({
          type: 'withdrawal' as const,
          amount: withdrawal.amount || 0,
          currency: withdrawal.currency,
          timestamp: this.timestampToDate(withdrawal.timestamp || 0),
          txId: withdrawal.txid || withdrawal.id || '',
          status: this.mapDepositStatus(withdrawal.status),
          fee: withdrawal.fee?.cost || 0,
          address: withdrawal.address,
          network: withdrawal.network,
        }));
    });
  }

  // ========================================
  // Private helpers
  // ========================================

  /**
   * Map CCXT deposit/withdrawal status to our standardized format
   * CCXT statuses: 'pending' | 'ok' | 'canceled' | 'failed'
   */
  private mapDepositStatus(status?: string): 'pending' | 'completed' | 'failed' {
    if (!status) return 'pending';

    const statusLower = status.toLowerCase();

    if (statusLower === 'ok' || statusLower === 'complete' || statusLower === 'success') {
      return 'completed';
    } else if (statusLower === 'pending' || statusLower === 'processing') {
      return 'pending';
    } else {
      return 'failed';
    }
  }

  /**
   * Test connection (override to use CCXT's built-in check)
   */
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

  // ========================================
  // NEW: Snapshot breakdown methods
  // ========================================

  /**
   * Detect supported market types on this exchange
   */
  async detectMarketTypes(): Promise<MarketType[]> {
    return this.withErrorHandling('detectMarketTypes', async () => {
      await this.exchange.loadMarkets();

      const marketTypes = new Set<MarketType>();

      for (const [marketId, market] of Object.entries(this.exchange.markets)) {
        if ((market as any).spot) marketTypes.add('spot');
        if ((market as any).swap) marketTypes.add('swap');
        if ((market as any).future) marketTypes.add('future');
        if ((market as any).option) marketTypes.add('option');
        if ((market as any).margin) marketTypes.add('margin');
      }

      const detected = Array.from(marketTypes);
      this.logger.info(`Detected market types for ${this.exchangeName}: ${detected.join(', ')}`);

      return detected;
    });
  }

  /**
   * Get balance for a specific market type
   * @param marketType - 'spot', 'swap', 'future', 'option', 'margin'
   */
  async getBalanceByMarket(marketType: MarketType): Promise<MarketBalanceData> {
    return this.withErrorHandling('getBalanceByMarket', async () => {
      // For unified account exchanges (Bitget, OKX, Bybit), we need special handling
      // because fetchBalance() returns the same total for all market types
      if (isUnifiedAccountExchange(this.exchangeName)) {
        return this.getBalanceForUnifiedAccount(marketType);
      }

      // Standard handling for non-unified accounts
      this.exchange.options['defaultType'] = marketType;

      const balance = await this.exchange.fetchBalance();

      // Extract USDT/USD balance
      const usdtBalance = balance['USDT'] || balance['USD'] || balance['USDC'];

      if (!usdtBalance) {
        return { equity: 0, available_margin: 0 };
      }

      // total = equity (with unrealized PnL)
      // free = available margin / collateral
      const equity = usdtBalance.total || 0;
      const availableMargin = usdtBalance.free || 0;

      return {
        equity,
        available_margin: availableMargin,
      };
    });
  }

  /**
   * Get balance breakdown for unified account exchanges
   *
   * Unified accounts (Bitget, OKX, Bybit) pool all assets together.
   * We need to calculate:
   * - Spot equity: Value of spot holdings (BTC, ETH, etc. converted to USDT)
   * - Swap equity: Margin used in futures/perpetuals positions
   */
  private async getBalanceForUnifiedAccount(marketType: MarketType): Promise<MarketBalanceData> {
    if (marketType === 'spot') {
      // For spot: Fetch REAL spot wallet balance (not unified account)
      // Bitget has separate wallets: 'spot' (traditional) vs 'crossed_margin' (unified)
      this.exchange.options['defaultType'] = 'spot';

      // Explicitly request SPOT account type to get the traditional spot wallet
      const params = { type: 'spot' };
      const balance = await this.exchange.fetchBalance(params);

      // DEBUG: Log the full balance structure to understand what we get
      this.logger.debug(`Bitget SPOT wallet (accountType='spot') balance:`, {
        usdtInfo: balance['USDT'],
        totalEquity: balance.total?.USDT || 0,
        allCurrencies: Object.keys(balance).filter(k => !['info', 'free', 'used', 'total', 'debt', 'timestamp', 'datetime'].includes(k))
      });

      let spotEquity = 0;

      // Sum value of all holdings in the spot wallet
      for (const [currency, value] of Object.entries(balance)) {
        // Skip special keys
        if (['info', 'free', 'used', 'total', 'debt', 'timestamp', 'datetime'].includes(currency)) {
          continue;
        }

        const holding = value as any;
        if (holding && holding.total && Number(holding.total) > 0) {
          // For crypto assets, the 'total' is already in USDT equivalent on most exchanges
          // If not, we'd need to fetch ticker prices and convert
          spotEquity += Number(holding.total) || 0;
          this.logger.debug(`Spot wallet holding: ${currency} = ${Number(holding.total).toFixed(2)} USDT`);
        }
      }

      this.logger.info(`Bitget SPOT wallet equity: ${spotEquity.toFixed(2)} USDT`);

      return {
        equity: spotEquity,
        available_margin: 0,
      };

    } else if (marketType === 'swap' || marketType === 'future') {
      // For swap/future: Get balance from UNIFIED/SWAP account
      // Note: Bitget doesn't support { type: 'cross' }, so we just use defaultType
      this.exchange.options['defaultType'] = 'swap';

      // Fetch swap balance WITHOUT additional params (Bitget doesn't support 'cross' type)
      const balance = await this.exchange.fetchBalance();

      // DEBUG: Log what we get from swap/unified account
      this.logger.debug(`Bitget SWAP/Unified account (defaultType='swap') balance:`, {
        usdtInfo: balance['USDT'],
        totalEquity: balance.total?.USDT || 0,
        allCurrencies: Object.keys(balance).filter(k => !['info', 'free', 'used', 'total', 'debt', 'timestamp', 'datetime'].includes(k))
      });

      // Get USDT balance (this is the unified margin)
      const usdtBalance = balance['USDT'] || balance['USD'] || balance['USDC'];

      if (!usdtBalance) {
        this.logger.warn(`No USDT balance found in swap/unified account for ${this.exchangeName}`);
        return { equity: 0, available_margin: 0 };
      }

      const equity = usdtBalance.total || 0;
      const availableMargin = usdtBalance.free || 0;

      this.logger.info(`Bitget SWAP/Unified account equity: ${equity.toFixed(2)} USDT, margin: ${availableMargin.toFixed(2)} USDT`);

      return {
        equity,
        available_margin: availableMargin,
      };

    } else {
      // Other market types (option, margin): return 0 for now
      return { equity: 0, available_margin: 0 };
    }
  }

  /**
   * Get executed trades for a specific market type
   * Uses fetchMyTrades to capture partial fills correctly
   */
  async getExecutedOrders(
    marketType: MarketType,
    since: Date
  ): Promise<ExecutedOrderData[]> {
    return this.withErrorHandling('getExecutedOrders', async () => {
      // Set market type
      this.exchange.options['defaultType'] = marketType;

      const sinceTimestamp = this.dateToTimestamp(since);

      let trades: ccxt.Trade[] = [];

      // Use fetchMyTrades to get all individual trade executions
      // This captures partial fills correctly (important for limit orders)
      if (this.exchange.has['fetchMyTrades']) {
        try {
          // Try fetching all trades for this market type (no symbol filter)
          trades = await this.exchange.fetchMyTrades(undefined, sinceTimestamp);
        } catch (error) {
          this.logger.warn(`fetchMyTrades failed for ${marketType}:`, error);

          // If fetchMyTrades without symbol fails, we need to iterate per symbol
          // For now, return empty (TODO: implement symbol caching)
          this.logger.warn(
            `Exchange requires symbol for fetchMyTrades. ` +
            `Consider implementing symbol caching for market type ${marketType}`
          );
          return [];
        }
      } else {
        this.logger.warn(`Exchange does not support fetchMyTrades for ${marketType}`);
        return [];
      }

      // Convert to ExecutedOrderData format
      // Note: We're returning TRADES, not orders (important for partial fills)
      return trades.map(trade => ({
        id: trade.id || `${trade.timestamp}`,
        timestamp: trade.timestamp || 0,
        symbol: trade.symbol,
        side: trade.side as 'buy' | 'sell',
        price: trade.price || 0,
        amount: trade.amount || 0,
        cost: trade.cost || (trade.amount || 0) * (trade.price || 0),
        fee: trade.fee ? {
          cost: trade.fee.cost || 0,
          currency: trade.fee.currency || this.defaultCurrency,
        } : undefined,
      }));
    });
  }

  /**
   * Get funding fees for swap markets (perpetual futures)
   * @param symbols - Symbols to fetch funding for (from recent orders)
   * @param since - Start date
   */
  async getFundingFees(symbols: string[], since: Date): Promise<FundingFeeData[]> {
    return this.withErrorHandling('getFundingFees', async () => {
      if (!this.exchange.has['fetchFundingHistory']) {
        this.logger.warn(`${this.exchangeName} does not support fetchFundingHistory`);
        return [];
      }

      const sinceTimestamp = this.dateToTimestamp(since);
      const allFunding: FundingFeeData[] = [];

      // Fetch funding history for each symbol
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
          this.logger.warn(`Failed to fetch funding for ${symbol}:`, error);
          // Continue with other symbols
        }
      }

      return allFunding;
    });
  }
}
