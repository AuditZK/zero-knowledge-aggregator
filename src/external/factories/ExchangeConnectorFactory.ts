import { container } from 'tsyringe';
import { IExchangeConnector } from '../../external/interfaces/IExchangeConnector';
import { ExchangeCredentials } from '../../types';
import { CcxtExchangeConnector } from '../../connectors/CcxtExchangeConnector';
import { IbkrFlexConnector } from '../../connectors/IbkrFlexConnector';
import { AlpacaConnector } from '../../connectors/AlpacaConnector';
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
 *   - MEXC (mexc) - Spot + Futures
 *   - OKX (okx) - Spot + Swap (Unified Account)
 *   - Bybit (bybit) - Spot + Swap (Unified Account)
 *   - And 100+ more crypto exchanges
 *
 * Supported stock brokers:
 *   - IBKR (ibkr) - Flex Query API
 *   - Alpaca (alpaca) - REST API
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
    'huobi': 'huobi',
    'kraken': 'kraken',

    // Add more as needed - CCXT supports 100+ exchanges
  };

  /**
   * List of stock brokers with custom connectors
   */
  private static readonly CUSTOM_BROKERS = ['ibkr', 'alpaca'];

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
