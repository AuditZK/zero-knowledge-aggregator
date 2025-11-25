import {
  IExchangeConnector,
  BalanceData,
  TradeData,
  PositionData,
  ExchangeFeature,
} from '../interfaces/IExchangeConnector';
import { ExchangeCredentials } from '../../types';
import { getLogger } from '../../utils/secure-enclave-logger';

/**
 * Base class for all exchange connectors
 *
 * Provides:
 * - Common error handling
 * - Logging infrastructure
 * - Feature detection with fallbacks
 * - Default implementations for optional methods
 *
 * Subclasses must implement:
 * - getBalance()
 * - getCurrentPositions()
 * - getTrades()
 * - getExchangeName()
 */
export abstract class BaseExchangeConnector implements IExchangeConnector {
  protected logger: any;
  protected credentials: ExchangeCredentials;

  constructor(credentials: ExchangeCredentials) {
    this.credentials = credentials;
    this.logger = getLogger(this.constructor.name);
  }

  // ========================================
  // Abstract methods (must be implemented)
  // ========================================

  /**
   * Get account balance - MUST be implemented
   */
  abstract getBalance(): Promise<BalanceData>;

  /**
   * Get current positions - MUST be implemented
   */
  abstract getCurrentPositions(): Promise<PositionData[]>;

  /**
   * Get trades in date range - MUST be implemented
   */
  abstract getTrades(startDate: Date, endDate: Date): Promise<TradeData[]>;

  /**
   * Get exchange name - MUST be implemented
   */
  abstract getExchangeName(): string;

  // ========================================
  // Default implementations (can override)
  // ========================================

  /**
   * Test connection by attempting to fetch balance
   * Can be overridden if exchange has specific health check endpoint
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.getBalance();
      this.logger.info(`${this.getExchangeName()}: Connection test successful`);
      return true;
    } catch (error) {
      this.logger.error(`${this.getExchangeName()}: Connection test failed`, error);
      return false;
    }
  }

  /**
   * Feature detection - default: all features supported
   * Subclasses should override to specify supported features
   */
  supportsFeature(feature: ExchangeFeature): boolean {
    const defaultSupported: ExchangeFeature[] = ['positions', 'trades'];
    return defaultSupported.includes(feature);
  }

  // ========================================
  // Protected helper methods
  // ========================================

  /**
   * Standardized error handling
   * Logs error and throws with context
   */
  protected handleError(error: any, context: string): never {
    const errorMessage = error?.message || 'Unknown error';
    const fullMessage = `${this.getExchangeName()}: ${context} failed - ${errorMessage}`;

    this.logger.error(fullMessage, {
      context,
      exchange: this.getExchangeName(),
      error: {
        name: error?.name,
        message: errorMessage,
        stack: error?.stack,
      },
    });

    throw new Error(fullMessage);
  }

  /**
   * Wrapper for async operations with standardized error handling
   * Reduces boilerplate try/catch in subclasses
   *
   * @example
   * async getBalance(): Promise<BalanceData> {
   *   return this.withErrorHandling('getBalance', async () => {
   *     const data = await this.api.fetchBalance();
   *     return this.createBalanceData(data.balance, data.equity);
   *   });
   * }
   */
  protected async withErrorHandling<T>(
    context: string,
    fn: () => Promise<T>
  ): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      this.handleError(error, context);
    }
  }

  /**
   * Create standardized BalanceData object
   * Calculates unrealizedPnl automatically (equity - balance)
   *
   * @param balance - Available balance (cash)
   * @param equity - Total equity (balance + unrealized PnL)
   * @param currency - Currency code (default: 'USDT')
   */
  protected createBalanceData(
    balance: number,
    equity: number,
    currency: string = 'USDT'
  ): BalanceData {
    return {
      balance,
      equity,
      unrealizedPnl: equity - balance,
      currency,
    };
  }

  /**
   * Helper: Convert timestamp to Date
   */
  protected toDate(timestamp: number | string): Date {
    if (typeof timestamp === 'string') {
      return new Date(timestamp);
    }
    return new Date(timestamp);
  }

  /**
   * Helper: Check if date is in range
   */
  protected isInDateRange(date: Date, startDate: Date, endDate: Date): boolean {
    return date >= startDate && date <= endDate;
  }

  /**
   * Helper: Parse float safely
   */
  protected parseFloat(value: string | number): number {
    if (typeof value === 'number') {
      return value;
    }
    const parsed = parseFloat(value);
    return isNaN(parsed) ? 0 : parsed;
  }

  /**
   * Helper: Sleep for rate limiting
   */
  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
