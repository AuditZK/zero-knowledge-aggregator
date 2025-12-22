import { BaseExchangeConnector } from './BaseExchangeConnector';
import { ExchangeFeature } from '../interfaces/IExchangeConnector';

/**
 * Base class for cryptocurrency exchange connectors
 *
 * Provides crypto-specific defaults:
 * - USDT as default currency
 * - Timestamp handling (milliseconds)
 * - Common crypto features (positions, trades, historical_data)
 *
 * Designed for exchanges like Binance, Bitget, MEXC, OKX, Bybit, etc.
 */
export abstract class CryptoExchangeConnector extends BaseExchangeConnector {
  /**
   * Default currency for crypto perpetuals/futures
   */
  protected readonly defaultCurrency = 'USDT';

  /**
   * Most crypto exchanges support these features
   * Subclasses can override if specific exchange differs
   */
  supportsFeature(feature: ExchangeFeature): boolean {
    const cryptoSupported: ExchangeFeature[] = [
      'positions',
      'trades',
      'historical_data',
    ];
    return cryptoSupported.includes(feature);
  }

  /**
   * Convert millisecond timestamp to Date (crypto standard)
   */
  protected timestampToDate(timestamp: number): Date {
    return new Date(timestamp);
  }

  /**
   * Convert Date to millisecond timestamp (crypto standard)
   */
  protected dateToTimestamp(date: Date): number {
    return date.getTime();
  }
}
