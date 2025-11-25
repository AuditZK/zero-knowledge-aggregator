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

  /**
   * Map common crypto status strings to standardized format
   * Override in subclass if exchange uses different status codes
   */
  protected mapCryptoStatus(
    status: string | number
  ): 'pending' | 'completed' | 'failed' {
    const statusStr = String(status).toLowerCase();

    if (
      statusStr.includes('success') ||
      statusStr.includes('completed') ||
      statusStr === 'finished' ||
      statusStr === '1' ||
      statusStr === '2'
    ) {
      return 'completed';
    } else if (
      statusStr.includes('pending') ||
      statusStr.includes('processing') ||
      statusStr === 'waiting' ||
      statusStr === '0'
    ) {
      return 'pending';
    } else {
      return 'failed';
    }
  }
}
