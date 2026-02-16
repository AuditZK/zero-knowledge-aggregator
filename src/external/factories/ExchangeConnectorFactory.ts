import { container } from 'tsyringe';
import { IExchangeConnector } from '../../external/interfaces/IExchangeConnector';
import { ExchangeCredentials } from '../../types';
import { CcxtExchangeConnector } from '../../connectors/CcxtExchangeConnector';
import { IbkrFlexConnector } from '../../connectors/IbkrFlexConnector';
import { AlpacaConnector } from '../../connectors/AlpacaConnector';
import { TradeStationConnector } from '../../connectors/TradeStationConnector';
import { HyperliquidConnector } from '../../connectors/HyperliquidConnector';
import { CTraderConnector } from '../../connectors/CTraderConnector';
import { LighterConnector } from '../../connectors/LighterConnector';
import { MockExchangeConnector } from '../../connectors/MockExchangeConnector';
import { DeribitConnector } from '../../connectors/DeribitConnector';
import { IbkrFlexService } from '../ibkr-flex-service';
import { getLogger } from '../../utils/secure-enclave-logger';

const logger = getLogger('ExchangeConnectorFactory');

/**
 * Factory for creating exchange connectors
 *
 * Architecture:
 * - Crypto exchanges: Unified via CCXT (100+ exchanges supported)
 * - Stock brokers: Individual connectors (IBKR, Alpaca, etc.)
 *
 * Usage:
 *   const connector = ExchangeConnectorFactory.create(credentials);
 *   const balance = await connector.getBalance();
 *
 * Supported crypto exchanges via CCXT:
 *   - Binance (binance) - Spot + Futures + Swap
 *   - Bitget (bitget) - Spot + Swap (Unified Account)
 *   - BingX (bingx) - Spot + Swap
 *   - MEXC (mexc) - Spot + Futures
 *   - OKX (okx) - Spot + Swap (Unified Account)
 *   - Bybit (bybit) - Spot + Swap (Unified Account)
 *   - And 100+ more crypto exchanges
 *
 * Supported stock brokers:
 *   - IBKR (ibkr) - Flex Query API
 *   - Alpaca (alpaca) - REST API
 *   - TradeStation (tradestation) - OAuth 2.0 REST API
 *
 * Supported CFD/Forex brokers:
 *   - cTrader (ctrader) - OAuth 2.0 REST API
 *
 * Supported crypto derivatives:
 *   - Deribit (deribit) - Options, Futures, Perpetuals (BTC/ETH settled)
 *
 * Supported DEX (wallet address only, no private key):
 *   - Hyperliquid (hyperliquid) - Public REST API (read-only)
 *   - Lighter (lighter) - Public REST API (read-only)
 */
export class ExchangeConnectorFactory {
  /**
   * List of crypto exchanges supported via CCXT
   * Mapped to CCXT exchange IDs
   */
  private static readonly CCXT_EXCHANGES: Record<string, string> = {
    // Binance - normalized to support spot + futures (like other exchanges)
    'binance': 'binance',
    'binance_futures': 'binance',
    'binanceusdm': 'binance',

    // Other major crypto exchanges
    'bitget': 'bitget',
    'mexc': 'mexc',
    'okx': 'okx',
    'bybit': 'bybit',
    'kucoin': 'kucoin', // Normalized to support spot + futures
    'coinbase': 'coinbase',
    'gate': 'gate',
    'bingx': 'bingx',
    'huobi': 'huobi',
    'kraken': 'kraken',

    // Add more as needed - CCXT supports 100+ exchanges
  };

  /**
   * List of stock brokers with custom connectors
   */
  private static readonly CUSTOM_BROKERS = ['ibkr', 'alpaca', 'tradestation', 'hyperliquid', 'lighter', 'ctrader', 'deribit', 'mock'];

  /**
   * Create an exchange connector instance
   * @param credentials Exchange credentials
   * @returns Exchange connector instance
   * @throws Error if exchange not supported
   */
  static create(credentials: ExchangeCredentials): IExchangeConnector {
    const exchange = credentials.exchange.toLowerCase();

    logger.info(`Creating connector for exchange: ${exchange}`);

    // Check if it's a stock broker with custom connector
    if (this.CUSTOM_BROKERS.includes(exchange)) {
      return this.createCustomBrokerConnector(exchange, credentials);
    }

    // Check if it's a crypto exchange supported by CCXT
    const ccxtExchangeId = this.CCXT_EXCHANGES[exchange];
    if (ccxtExchangeId) {
      logger.info(`Using CCXT connector for ${exchange} (CCXT ID: ${ccxtExchangeId})`);
      return new CcxtExchangeConnector(ccxtExchangeId, credentials);
    }

    // Unsupported exchange
    const error = `Unsupported exchange: ${exchange}. Supported: ${this.getSupportedExchanges().join(', ')}`;
    logger.error(error);
    throw new Error(error);
  }

  /**
   * Create custom broker connector (non-crypto)
   * Injects shared service singletons from DI container
   */
  private static createCustomBrokerConnector(
    exchange: string,
    credentials: ExchangeCredentials
  ): IExchangeConnector {
    switch (exchange) {
      case 'ibkr': {
        // Inject singleton IbkrFlexService to share cache across all IBKR connectors
        // This prevents rate limiting from multiple API calls per sync
        const flexService = container.resolve(IbkrFlexService);
        logger.info('Injecting shared IbkrFlexService singleton into connector');
        return new IbkrFlexConnector(credentials, flexService);
      }

      case 'alpaca':
        return new AlpacaConnector(credentials);

      case 'tradestation':
        return new TradeStationConnector(credentials);

      case 'hyperliquid':
        // DEX - only needs wallet address (apiKey), no private key required
        return new HyperliquidConnector(credentials);

      case 'lighter':
        // DEX - only needs wallet address (apiKey), no private key required
        return new LighterConnector(credentials);

      case 'ctrader':
        // CFD/Forex broker - OAuth 2.0 flow
        return new CTraderConnector(credentials);

      case 'deribit':
        // Crypto derivatives (options, futures, perps) - BTC/ETH settled
        return new DeribitConnector(credentials);

      case 'mock':
        // Stress test only - generates random trades, no external API
        return new MockExchangeConnector(credentials);

      default:
        throw new Error(`Custom broker ${exchange} not implemented`);
    }
  }

  /**
   * Get list of supported exchanges
   * @returns Array of supported exchange identifiers
   */
  static getSupportedExchanges(): string[] {
    const cryptoExchanges = Object.keys(this.CCXT_EXCHANGES);
    const brokers = this.CUSTOM_BROKERS;

    return [...cryptoExchanges, ...brokers];
  }

  /**
   * Check if exchange is supported
   * @param exchange Exchange identifier
   * @returns true if supported
   */
  static isSupported(exchange: string): boolean {
    const exchangeLower = exchange.toLowerCase();
    return (
      Object.hasOwn(this.CCXT_EXCHANGES, exchangeLower) ||
      this.CUSTOM_BROKERS.includes(exchangeLower)
    );
  }

  /**
   * Check if exchange is a crypto exchange (uses CCXT)
   */
  static isCryptoExchange(exchange: string): boolean {
    return Object.hasOwn(this.CCXT_EXCHANGES, exchange.toLowerCase());
  }
}
