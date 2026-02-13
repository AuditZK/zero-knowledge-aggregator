import { BaseExchangeConnector } from '../external/base/BaseExchangeConnector';
import {
  BalanceData,
  PositionData,
  TradeData,
} from '../external/interfaces/IExchangeConnector';
import { ExchangeCredentials } from '../types';

/**
 * Mock exchange connector for stress testing.
 *
 * Trade count is encoded in the apiKey field (e.g. apiKey: "50" → 50 trades).
 * Generates random trades in-memory, no external API calls.
 * Goes through the real aggregation pipeline (snapshot creation, DB writes).
 *
 * Dev/test only.
 */
export class MockExchangeConnector extends BaseExchangeConnector {
  private readonly tradeCount: number;

  private static readonly SYMBOLS = [
    'BTC/USDT', 'ETH/USDT', 'SOL/USDT', 'XRP/USDT', 'DOGE/USDT',
    'ADA/USDT', 'AVAX/USDT', 'DOT/USDT', 'LINK/USDT', 'MATIC/USDT',
  ];

  private static readonly PRICES: Record<string, number> = {
    'BTC/USDT': 45000, 'ETH/USDT': 2500, 'SOL/USDT': 120,
    'XRP/USDT': 0.6, 'DOGE/USDT': 0.08, 'ADA/USDT': 0.45,
    'AVAX/USDT': 35, 'DOT/USDT': 7, 'LINK/USDT': 15, 'MATIC/USDT': 0.8,
  };

  constructor(credentials: ExchangeCredentials) {
    super(credentials);
    this.tradeCount = parseInt(credentials.apiKey, 10) || 10;
    this.logger.info(`MockExchangeConnector: will generate ${this.tradeCount} trades per sync`);
  }

  getExchangeName(): string {
    return 'mock';
  }

  async testConnection(): Promise<boolean> {
    return true;
  }

  async getBalance(): Promise<BalanceData> {
    const equity = 10000 + Math.random() * 90000;
    const pnl = (Math.random() - 0.3) * equity * 0.1;
    return this.createBalanceData(equity - pnl, equity, 'USDT');
  }

  async getCurrentPositions(): Promise<PositionData[]> {
    const count = Math.floor(Math.random() * 5);
    const positions: PositionData[] = [];

    for (let i = 0; i < count; i++) {
      const symbol = MockExchangeConnector.SYMBOLS[Math.floor(Math.random() * MockExchangeConnector.SYMBOLS.length)] as string;
      const basePrice = MockExchangeConnector.PRICES[symbol] ?? 100;
      const entryPrice = basePrice * (0.95 + Math.random() * 0.1);
      const markPrice = basePrice * (0.95 + Math.random() * 0.1);
      const size = Math.random() * 10;
      const side = Math.random() > 0.5 ? 'long' : 'short' as const;
      const pnlDir = side === 'long' ? 1 : -1;

      positions.push({
        symbol,
        side,
        size,
        entryPrice,
        markPrice,
        unrealizedPnl: (markPrice - entryPrice) * size * pnlDir,
        leverage: Math.ceil(Math.random() * 10),
      });
    }

    return positions;
  }

  async getTrades(startDate: Date, endDate: Date): Promise<TradeData[]> {
    const trades: TradeData[] = [];
    const range = endDate.getTime() - startDate.getTime();

    for (let i = 0; i < this.tradeCount; i++) {
      const symbol = MockExchangeConnector.SYMBOLS[Math.floor(Math.random() * MockExchangeConnector.SYMBOLS.length)] as string;
      const basePrice = MockExchangeConnector.PRICES[symbol] ?? 100;
      const price = basePrice * (0.9 + Math.random() * 0.2);
      const quantity = (Math.random() * 100) / price * basePrice;

      trades.push({
        tradeId: `mock-${Date.now()}-${i}`,
        symbol,
        side: Math.random() > 0.5 ? 'buy' : 'sell',
        quantity,
        price,
        fee: price * quantity * 0.001,
        feeCurrency: 'USDT',
        timestamp: new Date(startDate.getTime() + Math.random() * range),
      });
    }

    // Simulate processing time proportional to trade count
    await this.sleep(this.tradeCount * 2);

    return trades;
  }
}
