import { BaseExchangeConnector } from './BaseExchangeConnector';
import { ExchangeFeature } from '../interfaces/IExchangeConnector';

/**
 * Base class for REST-based stock broker connectors
 *
 * Provides common infrastructure for brokers using standard REST APIs:
 * - TD Ameritrade (OAuth 2.0)
 * - E*TRADE (OAuth 1.0a)
 * - Alpaca (API Key)
 * - And other similar brokers
 *
 * Features:
 * - HTTP request wrapper with authentication
 * - JSON parsing
 * - USD as default currency
 * - Real-time data access
 *
 * Subclasses must implement:
 * - getAuthHeaders() - Authentication headers for requests
 * - apiBaseUrl - Base URL for API
 */
export abstract class RestBrokerConnector extends BaseExchangeConnector {
  /**
   * Base URL for broker API
   * Example: 'https://api.alpaca.markets/v2'
   */
  protected abstract apiBaseUrl: string;

  /**
   * Default currency for stock brokers (USD)
   */
  protected readonly defaultCurrency = 'USD';

  /**
   * Get authentication headers for API requests
   * Subclasses implement based on auth method (OAuth 2.0, OAuth 1.0a, API Key)
   */
  protected abstract getAuthHeaders(): Promise<Record<string, string>>;

  /**
   * Most stock brokers support these features
   * Override in subclass if specific broker differs
   */
  supportsFeature(feature: ExchangeFeature): boolean {
    const brokerSupported: ExchangeFeature[] = [
      'positions',
      'trades',
      'historical_data',
      // Note: capital_flows usually NOT supported via API for brokers
    ];
    return brokerSupported.includes(feature);
  }

  // ========================================
  // Protected helper methods
  // ========================================

  /**
   * Make HTTP request to broker API
   * Handles authentication, JSON parsing, and error handling
   *
   * @param method - HTTP method
   * @param endpoint - API endpoint (e.g., '/accounts')
   * @param params - Query parameters or request body
   * @returns Parsed JSON response
   */
  protected async makeRequest<T>(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    endpoint: string,
    params?: Record<string, any>
  ): Promise<T> {
    const headers = await this.getAuthHeaders();
    const url = `${this.apiBaseUrl}${endpoint}`;

    // Build query string for GET requests
    let fullUrl = url;
    if (method === 'GET' && params) {
      const queryString = new URLSearchParams(
        Object.entries(params).reduce((acc, [key, value]) => {
          acc[key] = String(value);
          return acc;
        }, {} as Record<string, string>)
      ).toString();
      fullUrl = `${url}?${queryString}`;
    }

    const options: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    };

    // Add body for POST/PUT requests
    if ((method === 'POST' || method === 'PUT') && params) {
      options.body = JSON.stringify(params);
    }

    const response = await fetch(fullUrl, options);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `HTTP ${response.status} ${response.statusText}: ${errorText}`
      );
    }

    // Handle empty responses (204 No Content)
    if (response.status === 204) {
      return {} as T;
    }

    return (await response.json()) as T;
  }

  /**
   * Convert ISO date string to Date (broker standard)
   */
  protected isoStringToDate(isoString: string): Date {
    return new Date(isoString);
  }

  /**
   * Convert Date to ISO string (broker standard)
   */
  protected dateToIsoString(date: Date): string {
    return date.toISOString();
  }

  /**
   * Parse broker-specific error response
   * Override in subclass if broker uses custom error format
   */
  protected parseBrokerError(error: any): string {
    if (error.response?.data?.message) {
      return error.response.data.message;
    }
    if (error.message) {
      return error.message;
    }
    return 'Unknown broker error';
  }
}
