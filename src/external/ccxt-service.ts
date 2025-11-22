import { injectable } from 'tsyringe';
import ccxt from 'ccxt';
import * as ccxtTypes from 'ccxt';
import { ExchangeCredentials, TradeData, Position } from '../types';
import { getLogger } from '../utils/logger.service';

const logger = getLogger('CCXTService');

export interface CCXTTrade {
  id: string;
  order?: string;
  symbol: string;
  type: 'market' | 'limit'; // Order type (market/limit)
  side: 'buy' | 'sell'; // Trade direction (buy/sell) - maps to our Trade.type
  amount: number;
  price: number;
  cost: number;
  fee: {
    cost: number;
    currency: string;
  };
  timestamp: number;
  datetime: string;
}

@injectable()
export class CCXTService {
  private exchanges: Map<string, ccxtTypes.Exchange> = new Map();

  constructor() {
    // No dependencies to inject - uses ccxt library directly
  }

  getSupportedExchanges(): string[] {
    // Note: IBKR and Alpaca are handled separately (not CCXT-supported)
    return ['alpaca', 'binance', 'bitget', 'bybit', 'coinbase', 'kraken', 'kucoin', 'mexc', 'okx'];
  }

  async createExchangeInstance(credentials: ExchangeCredentials): Promise<ccxtTypes.Exchange | null> {
    try {
      const exchangeId = credentials.exchange.toLowerCase();

      if (!this.getSupportedExchanges().includes(exchangeId)) {
        throw new Error(`Unsupported exchange: ${exchangeId}`);
      }

      // Handle non-CCXT exchanges separately
      if (exchangeId === 'alpaca') {
        const { AlpacaApiService } = require('./alpaca-api-service');
        const alpacaService = new AlpacaApiService(credentials);
        return alpacaService; // Return Alpaca service as exchange interface
      }

      const ExchangeClass = ccxt[exchangeId as keyof typeof ccxt] as typeof ccxt.Exchange;

      if (!ExchangeClass) {
        throw new Error(`Exchange class not found: ${exchangeId}`);
      }

      const config: any = {
        apiKey: credentials.apiKey,
        secret: credentials.apiSecret,
        sandbox: false,
        enableRateLimit: true,
        options: {
          defaultType: 'swap', // Use perpetual futures (swap) instead of spot
        },
      };

      // Add passphrase for exchanges that need it
      if (credentials.passphrase) {
        if (['coinbase', 'okx', 'kucoin'].includes(exchangeId)) {
          config.passphrase = credentials.passphrase;
        } else if (exchangeId === 'bitget') {
          // Bitget uses "password" instead of "passphrase"
          config.password = credentials.passphrase;
        }
      }

      const exchange = new ExchangeClass(config);
      const connectionKey = `${credentials.userUid}-${exchangeId}-${credentials.label}`;
      this.exchanges.set(connectionKey, exchange);

      return exchange;
    } catch (error) {
      logger.error(`Failed to create exchange instance for ${credentials.exchange}`, error);
      return null;
    }
  }

  async testConnection(credentials: ExchangeCredentials): Promise<boolean> {
    try {
      const exchangeId = credentials.exchange.toLowerCase();

      // Handle Alpaca test connection
      if (exchangeId === 'alpaca') {
        const { AlpacaApiService } = require('./alpaca-api-service');
        const alpacaService = new AlpacaApiService(credentials);
        return await alpacaService.testConnection();
      }

      const exchange = await this.createExchangeInstance(credentials);
      if (!exchange) {
        logger.error(`Failed to create exchange instance for ${credentials.exchange}`);
        return false;
      }

      // Test connection by fetching balance
      await exchange.fetchBalance();
      return true;
    } catch (error: any) {
      logger.error(`Connection test failed for ${credentials.exchange}`, error, {
        name: error.name,
        message: error.message,
        code: error.code,
      });
      return false;
    }
  }

  async fetchTrades(
    credentials: ExchangeCredentials,
    symbol?: string,
    since?: number,
    limit: number = 1000,
  ): Promise<TradeData[]> {
    try {
      const exchangeId = credentials.exchange.toLowerCase();

      // Handle Alpaca fetch trades
      if (exchangeId === 'alpaca') {
        const { AlpacaApiService } = require('./alpaca-api-service');
        const alpacaService = new AlpacaApiService(credentials);

        const days = since ? Math.ceil((Date.now() - since) / (1000 * 60 * 60 * 24)) : 90;
        const alpacaTrades = await alpacaService.getTradeHistory(days);

        return alpacaTrades.map(trade => ({
          tradeId: `${trade.symbol}_${trade.transaction_time}`,
          exchange: 'alpaca',
          userUid: credentials.userUid,
          symbol: trade.symbol || '',
          type: trade.side as 'buy' | 'sell',
          price: parseFloat(trade.price || '0'),
          amount: parseFloat(trade.qty || '0'),
          fee: 0, // Alpaca has zero commission
          feeCurrency: 'USD',
          datetime: trade.transaction_time,
          timestamp: new Date(trade.transaction_time).getTime(),
          orderId: '',
          realizedPnl: 0,
          unrealizedPnl: 0,
        }));
      }

      const exchange = await this.createExchangeInstance(credentials);
      if (!exchange) {
        throw new Error('Failed to create exchange instance');
      }

      let trades: CCXTTrade[] = [];

      if (symbol) {
        // Fetch trades for specific symbol
        const rawTrades = await exchange.fetchMyTrades(symbol, since, limit);
        trades = rawTrades as CCXTTrade[];
      } else {
        // Fetch all trades - FIXED: Get ALL symbols, not just 10
        const markets = await exchange.loadMarkets();
        const allSymbols = Object.keys(markets);

        // Filter for perpetual futures and active symbols
        const activeSymbols = allSymbols.filter(sym => {
          const market = markets[sym];
          return market.active && (market.type === 'future' || sym.includes(':') || sym.includes('PERP'));
        });

        for (const sym of activeSymbols) {
          try {
            const symbolTrades = await exchange.fetchMyTrades(sym, since, Math.min(limit, 500));
            if (symbolTrades.length > 0) {
              trades.push(...(symbolTrades as CCXTTrade[]));

            }

            // Rate limiting
            await this.sleep(exchange.rateLimit || 100);
          } catch (error) {
            logger.warn(`Failed to fetch trades for ${sym}`, error);
          }
        }
      }

      return trades.map(trade => this.convertCCXTTradeToTradeData(trade, credentials.userUid));
    } catch (error) {
      logger.error(`Failed to fetch trades from ${credentials.exchange}`, error);
      throw error;
    }
  }

  async fetchAllHistoricalTrades(credentials: ExchangeCredentials, activeSymbolsOnly: boolean = true): Promise<TradeData[]> {
    try {
      const exchange = await this.createExchangeInstance(credentials);
      if (!exchange) {
        throw new Error('Failed to create exchange instance');
      }

      const allTrades: TradeData[] = [];
      const markets = await exchange.loadMarkets();
      let symbols = Object.keys(markets);

      // Pre-filter symbols with recent activity (volume > 0) for perpetual futures
      if (activeSymbolsOnly) {
        try {
          // For perpetual futures, we need to check the correct market type
          const tickers = await exchange.fetchTickers();
          symbols = symbols.filter(symbol => {
            const ticker = tickers[symbol];
            // Check if it's a perpetual future symbol and has volume
            const isPerp = symbol.includes(':') || symbol.includes('PERP') || symbol.includes('/USDT:USDT') || symbol.includes('/USD:USD');
            const hasVolume = ticker && (ticker.quoteVolume > 0 || ticker.baseVolume > 0);
            return isPerp && hasVolume;
          });

        } catch (error) {
          logger.warn('Could not filter symbols by volume, using all symbols', error);
        }
      }

      // Process symbols in parallel batches to optimize performance
      const batchSize = Math.min(10, Math.max(1, Math.floor(symbols.length / 20))); // Dynamic batch size
      const symbolBatches = this.chunkArray(symbols, batchSize);

      for (let i = 0; i < symbolBatches.length; i++) {
        const batch = symbolBatches[i];

        // Process batch in parallel
        const batchPromises = batch.map(symbol => this.fetchSymbolHistoricalTrades(exchange, symbol, credentials.userUid, credentials.exchange));
        const batchResults = await Promise.allSettled(batchPromises);

        // Collect successful results
        batchResults.forEach((result, index) => {
          if (result.status === 'fulfilled' && result.value.length > 0) {
            allTrades.push(...result.value);

          } else if (result.status === 'rejected') {
            logger.warn(`Failed to fetch trades for ${batch[index]}`, result.reason);
          }
        });

        // Rate limiting between batches
        if (i < symbolBatches.length - 1) {
          await this.sleep(exchange.rateLimit || 200);
        }
      }

      return allTrades;
    } catch (error) {
      logger.error(`Failed to fetch historical trades from ${credentials.exchange}`, error);
      throw error;
    }
  }

  private async fetchSymbolHistoricalTrades(exchange: ccxtTypes.Exchange, symbol: string, userUid: string, exchangeName: string): Promise<TradeData[]> {
    try {
      // FIXED: Fetch ALL available trades, not just last 89 days
      // Most exchanges allow fetching historical data without date limit
      let since = undefined; // Start from the beginning
      let hasMore = true;
      const symbolTrades: CCXTTrade[] = [];
      let pagesProcessed = 0;
      const maxPages = 100; // Increased limit for complete history

      while (hasMore && pagesProcessed < maxPages) {
        const trades = await exchange.fetchMyTrades(symbol, since, 1000);

        if (trades.length === 0) {
          hasMore = false;
        } else {
          symbolTrades.push(...(trades as CCXTTrade[]));
          // Move to next page using last trade timestamp
          since = trades[trades.length - 1].timestamp + 1;
          pagesProcessed++;

          // Micro rate limiting within symbol fetch
          await this.sleep(50);
        }

        // Safety check to avoid infinite loops
        if (symbolTrades.length > 50000) {
          logger.warn(`Too many trades for ${symbol}, stopping fetch`, { count: symbolTrades.length });
          break;
        }
      }

      if (symbolTrades.length > 0) {
        const oldestDate = new Date(symbolTrades[0].timestamp).toISOString();
        const newestDate = new Date(symbolTrades[symbolTrades.length - 1].timestamp).toISOString();

      }

      return symbolTrades.map(trade => this.convertCCXTTradeToTradeData(trade, userUid, exchangeName));
    } catch (error) {
      // Don't log individual symbol errors here, let caller handle
      throw error;
    }
  }

  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }

  private convertCCXTTradeToTradeData(trade: CCXTTrade, userUid: string, exchange?: string): TradeData {
    return {
      userUid,
      exchangeTradeId: trade.id,
      exchange: exchange || 'unknown',
      symbol: trade.symbol,
      type: trade.side, // Already 'buy' | 'sell'
      quantity: trade.amount,
      price: trade.price,
      fees: trade.fee?.cost || 0,
      timestamp: new Date(trade.timestamp),
      orderId: trade.order,
    };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Fetch current open positions from exchange
   */
  async fetchCurrentPositions(credentials: ExchangeCredentials): Promise<Position[]> {
    try {
      const exchangeId = credentials.exchange.toLowerCase();

      // Handle Alpaca fetch positions
      if (exchangeId === 'alpaca') {
        const { AlpacaApiService } = require('./alpaca-api-service');
        const alpacaService = new AlpacaApiService(credentials);

        const alpacaPositions = await alpacaService.getCurrentPositions();

        return alpacaPositions.map(pos => ({
          positionId: `${pos.symbol}_${pos.asset_id}`,
          exchange: 'alpaca',
          userUid: credentials.userUid,
          symbol: pos.symbol,
          side: pos.side as 'long' | 'short',
          contracts: parseFloat(pos.qty),
          entryPrice: parseFloat(pos.avg_entry_price),
          markPrice: parseFloat(pos.current_price),
          unrealizedPnl: parseFloat(pos.unrealized_pl),
          realizedPnl: 0,
          marginUsed: parseFloat(pos.cost_basis),
          leverage: 1, // Alpaca doesn't use leverage for stocks
          timestamp: Date.now(),
          datetime: new Date().toISOString(),
        }));
      }

      const exchange = await this.createExchangeInstance(credentials);
      if (!exchange) {
        throw new Error('Failed to create exchange instance');
      }

      // Check if exchange supports position fetching
      if (!exchange.has['fetchPositions']) {
        logger.warn(`Exchange ${credentials.exchange} does not support position fetching`);
        return [];
      }

      const positions = await exchange.fetchPositions();

      // Filter only open positions with size > 0
      const openPositions = positions.filter(pos =>
        pos.contracts !== 0 && pos.side !== undefined,
      );

      return openPositions.map(pos => this.convertCCXTPositionToPosition(pos, credentials.userUid, credentials.exchange));
    } catch (error) {
      logger.error(`Failed to fetch positions from ${credentials.exchange}`, error);
      throw error;
    }
  }

  /**
   * Fetch historical positions (closed positions) from exchange
   * With pagination to fetch ALL historical positions
   */
  async fetchHistoricalPositions(credentials: ExchangeCredentials, since?: number, limit: number = 200): Promise<Position[]> {
    try {
      const exchange = await this.createExchangeInstance(credentials);
      if (!exchange) {
        throw new Error('Failed to create exchange instance');
      }

      // Check if exchange supports historical position fetching
      if (!exchange.has['fetchPositionsHistory']) {
        logger.warn(`Exchange ${credentials.exchange} does not support historical position fetching`);
        return [];
      }

      // Fetching historical positions with pagination

      const allPositions: any[] = [];
      // Set default start date to 89 days ago to respect API limits
      let currentSince = since || new Date(Date.now() - 89 * 24 * 60 * 60 * 1000).getTime();
      let page = 0;
      const maxPages = 100; // Safety limit

      while (page < maxPages) {
        page++;

        try {
          const positions = await exchange.fetchPositionsHistory(undefined, currentSince, limit);

          if (positions.length === 0) {
            // End of historical positions reached
            break;
          }

          allPositions.push(...positions);
          // Page ${page}: ${positions.length} positions

          // Update since for next page (use timestamp of last position + 1)
          if (positions.length > 0) {
            const lastPosition = positions[positions.length - 1];
            if (lastPosition.timestamp) {
              currentSince = lastPosition.timestamp + 1;
            } else {
              // If no timestamp, we can't paginate properly
              break;
            }
          }

          // If we got fewer positions than the limit, we've reached the end
          if (positions.length < limit) {
            // Reached end of positions
            break;
          }

          // Rate limiting between requests
          await this.sleep(200);

        } catch (error) {
          logger.error(`Error fetching historical positions page ${page}`, error);
          break;
        }
      }

      // Fetched ${allPositions.length} historical positions

      return allPositions.map(pos => this.convertCCXTPositionToPosition(pos, credentials.userUid, credentials.exchange, true));
    } catch (error) {
      logger.error(`Failed to fetch historical positions from ${credentials.exchange}`, error);
      throw error;
    }
  }

  /**
   * Convert CCXT position to our Position interface
   */
  private convertCCXTPositionToPosition(ccxtPosition: any, userUid: string, exchange: string, isClosed: boolean = false): Position {
    const id = `${userUid}-${exchange}-${ccxtPosition.symbol}-${ccxtPosition.timestamp || Date.now()}`;

    // Processing CCXT position for ${ccxtPosition.symbol}

    // Enhanced field mapping for different exchanges
    let unrealizedPnl = 0;
    let realizedPnl = 0;

    // Try multiple field names for unrealized PnL
    if (ccxtPosition.unrealizedPnl !== undefined) {
      unrealizedPnl = ccxtPosition.unrealizedPnl;
    } else if (ccxtPosition.unrealizedPL !== undefined) {
      unrealizedPnl = ccxtPosition.unrealizedPL; // Bitget specific
    } else if (ccxtPosition.percentage !== undefined) {
      unrealizedPnl = ccxtPosition.percentage;
    } else if (ccxtPosition.pnl !== undefined) {
      unrealizedPnl = ccxtPosition.pnl;
    } else if (ccxtPosition.profit !== undefined) {
      unrealizedPnl = ccxtPosition.profit;
    }

    // Try multiple field names for realized PnL
    // IMPORTANT: Use netProfit for Bitget (after fees), not pnl (before fees)
    if (ccxtPosition.netProfit !== undefined) {
      realizedPnl = ccxtPosition.netProfit; // Bitget specific - profit after fees ✅
    } else if (ccxtPosition.realizedPnl !== undefined) {
      realizedPnl = ccxtPosition.realizedPnl;
    } else if (ccxtPosition.realizedPL !== undefined) {
      realizedPnl = ccxtPosition.realizedPL; // Bitget fallback
    } else if (ccxtPosition.achievedProfits !== undefined) {
      realizedPnl = ccxtPosition.achievedProfits; // Bitget fallback
    }

    // PnL mapping: unrealized=${unrealizedPnl}, realized=${realizedPnl}

    return {
      id,
      userUid,
      exchange,
      symbol: ccxtPosition.symbol,
      side: ccxtPosition.side === 'long' ? 'long' : 'short',
      size: Math.abs(ccxtPosition.contracts || ccxtPosition.size || 0),
      entryPrice: ccxtPosition.entryPrice || ccxtPosition.averagePrice || ccxtPosition.openPriceAvg || 0,
      markPrice: ccxtPosition.markPrice || ccxtPosition.lastPrice || 0,
      realizedPnl: isClosed ? realizedPnl : undefined,
      unrealizedPnl,
      timestamp: new Date(ccxtPosition.timestamp || Date.now()),
      status: isClosed ? 'closed' : 'open',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  closeExchangeConnections(): void {
    this.exchanges.clear();
  }
}