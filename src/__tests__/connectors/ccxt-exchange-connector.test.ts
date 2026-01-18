import { CcxtExchangeConnector } from '../../connectors/CcxtExchangeConnector';
import { ExchangeCredentials } from '../../types';
import * as ccxt from 'ccxt';

// Mock ccxt
jest.mock('ccxt', () => {
  const mockExchange = {
    fetchBalance: jest.fn(),
    fetchPositions: jest.fn(),
    fetchMyTrades: jest.fn(),
    fetchClosedOrders: jest.fn(),
    fetchFundingHistory: jest.fn(),
    loadMarkets: jest.fn(),
    markets: {},
    options: { defaultType: 'future' },
    has: {
      fetchClosedOrders: true,
      fetchPositions: true,
      fetchMyTrades: true,
      fetchFundingHistory: true,
    },
  };

  return {
    binance: jest.fn(() => mockExchange),
    kraken: jest.fn(() => mockExchange),
  };
});

describe('CcxtExchangeConnector', () => {
  let connector: CcxtExchangeConnector;
  let mockExchange: jest.Mocked<ccxt.Exchange>;

  const mockCredentials: ExchangeCredentials = {
    userUid: 'user_test123',
    exchange: 'binance',
    label: 'Main Account',
    apiKey: 'test_api_key',
    apiSecret: 'test_api_secret',
    passphrase: 'test_passphrase',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    connector = new CcxtExchangeConnector('binance', mockCredentials);
    // Get the mock exchange instance
    mockExchange = (ccxt.binance as jest.Mock).mock.results[0]?.value;
  });

  describe('constructor', () => {
    it('should create connector with valid exchange', () => {
      expect(connector).toBeDefined();
      expect(connector.getExchangeName()).toBe('binance');
    });

    it('should throw error for unsupported exchange', () => {
      expect(() => new CcxtExchangeConnector('unsupported_exchange' as keyof typeof ccxt, mockCredentials))
        .toThrow("Exchange 'unsupported_exchange' not supported by CCXT.");
    });
  });

  describe('getExchangeName', () => {
    it('should return exchange name', () => {
      expect(connector.getExchangeName()).toBe('binance');
    });
  });

  describe('getBalance', () => {
    it('should return balance with USDT', async () => {
      mockExchange.fetchBalance.mockResolvedValue({
        USDT: { free: 1000, total: 5000 },
      } as unknown as ccxt.Balances);

      const result = await connector.getBalance();

      expect(result.balance).toBe(1000);
      expect(result.equity).toBe(5000);
    });

    it('should return balance with USD if no USDT', async () => {
      mockExchange.fetchBalance.mockResolvedValue({
        USD: { free: 500, total: 2500 },
      } as unknown as ccxt.Balances);

      const result = await connector.getBalance();

      expect(result.balance).toBe(500);
      expect(result.equity).toBe(2500);
    });

    it('should return zero balance when no USDT/USD found', async () => {
      mockExchange.fetchBalance.mockResolvedValue({
        BTC: { free: 1, total: 2 },
      } as unknown as ccxt.Balances);

      const result = await connector.getBalance();

      expect(result.balance).toBe(0);
      expect(result.equity).toBe(0);
    });
  });

  describe('getCurrentPositions', () => {
    it('should return positions with correct mapping', async () => {
      mockExchange.fetchPositions.mockResolvedValue([
        {
          symbol: 'BTC/USDT',
          side: 'long',
          contracts: 0.5,
          entryPrice: 50000,
          markPrice: 51000,
          unrealizedPnl: 500,
          leverage: 10,
          liquidationPrice: 45000,
          marginMode: 'cross',
        },
        {
          symbol: 'ETH/USDT',
          side: 'short',
          contracts: 2,
          entryPrice: 3000,
          markPrice: 2900,
          unrealizedPnl: 200,
          leverage: 5,
          liquidationPrice: 3500,
          marginMode: 'isolated',
        },
      ] as unknown as ccxt.Position[]);

      const result = await connector.getCurrentPositions();

      expect(result.length).toBe(2);
      expect(result[0]!.symbol).toBe('BTC/USDT');
      expect(result[0]!.side).toBe('long');
      expect(result[0]!.size).toBe(0.5);
      expect(result[0]!.leverage).toBe(10);
      expect(result[1]!.symbol).toBe('ETH/USDT');
      expect(result[1]!.side).toBe('short');
    });

    it('should filter out positions with zero contracts', async () => {
      mockExchange.fetchPositions.mockResolvedValue([
        { symbol: 'BTC/USDT', contracts: 0.5 },
        { symbol: 'ETH/USDT', contracts: 0 },
      ] as unknown as ccxt.Position[]);

      const result = await connector.getCurrentPositions();

      expect(result.length).toBe(1);
      expect(result[0]!.symbol).toBe('BTC/USDT');
    });
  });

  describe('testConnection', () => {
    it('should return true for successful connection', async () => {
      mockExchange.fetchBalance.mockResolvedValue({} as ccxt.Balances);

      const result = await connector.testConnection();

      expect(result).toBe(true);
    });

    it('should return false for failed connection', async () => {
      mockExchange.fetchBalance.mockRejectedValue(new Error('Connection failed'));

      const result = await connector.testConnection();

      expect(result).toBe(false);
    });
  });

  describe('detectMarketTypes', () => {
    it('should detect market types from loaded markets', async () => {
      mockExchange.loadMarkets.mockResolvedValue({});
      mockExchange.markets = {
        'BTC/USDT': { spot: true, swap: false },
        'BTC/USDT:USDT': { spot: false, swap: true },
        'ETH/USDT': { spot: true, margin: true },
      } as unknown as ccxt.Dictionary<ccxt.Market>;

      const result = await connector.detectMarketTypes();

      expect(result).toContain('spot');
      expect(result).toContain('swap');
      expect(result).toContain('margin');
    });

    it('should cache market types', async () => {
      mockExchange.loadMarkets.mockResolvedValue({});
      mockExchange.markets = {
        'BTC/USDT': { spot: true },
      } as unknown as ccxt.Dictionary<ccxt.Market>;

      await connector.detectMarketTypes();
      await connector.detectMarketTypes();

      // Should only load markets once due to caching
      expect(mockExchange.loadMarkets).toHaveBeenCalledTimes(1);
    });
  });

  describe('getBalanceByMarket', () => {
    it('should return balance for specific market type', async () => {
      mockExchange.fetchBalance.mockResolvedValue({
        USDT: { free: 1000, total: 5000 },
      } as unknown as ccxt.Balances);

      const result = await connector.getBalanceByMarket('spot');

      expect(result.equity).toBe(5000);
      expect(result.available_margin).toBe(1000);
    });

    it('should return zero for market with no balance', async () => {
      mockExchange.fetchBalance.mockResolvedValue({
        BTC: { free: 1, total: 2 },
      } as unknown as ccxt.Balances);

      const result = await connector.getBalanceByMarket('swap');

      expect(result.equity).toBe(0);
      expect(result.available_margin).toBe(0);
    });
  });

  describe('getExecutedOrders', () => {
    it('should return executed orders for market type', async () => {
      mockExchange.fetchClosedOrders.mockResolvedValue([
        { symbol: 'BTC/USDT' },
      ] as unknown as ccxt.Order[]);
      mockExchange.fetchMyTrades.mockResolvedValue([
        {
          id: 'trade1',
          symbol: 'BTC/USDT',
          side: 'buy',
          amount: 0.1,
          price: 50000,
          cost: 5000,
          fee: { cost: 5, currency: 'USDT' },
          timestamp: Date.now(),
        },
      ] as unknown as ccxt.Trade[]);

      const result = await connector.getExecutedOrders('spot', new Date('2024-01-01'));

      expect(result.length).toBe(1);
      expect(result[0]!.symbol).toBe('BTC/USDT');
      expect(result[0]!.side).toBe('buy');
    });

    it('should return empty array when fetchMyTrades not supported', async () => {
      mockExchange.has['fetchMyTrades'] = false;

      const result = await connector.getExecutedOrders('spot', new Date('2024-01-01'));

      expect(result).toEqual([]);

      // Reset for other tests
      mockExchange.has['fetchMyTrades'] = true;
    });
  });

  describe('getFundingFees', () => {
    it('should return funding fees for symbols', async () => {
      mockExchange.fetchFundingHistory.mockResolvedValue([
        { timestamp: Date.now(), symbol: 'BTC/USDT:USDT', amount: -0.5 },
        { timestamp: Date.now(), symbol: 'BTC/USDT:USDT', amount: 0.3 },
      ] as unknown as ccxt.FundingHistory[]);

      const result = await connector.getFundingFees(['BTC/USDT:USDT'], new Date('2024-01-01'));

      expect(result.length).toBe(2);
      expect(result[0]!.symbol).toBe('BTC/USDT:USDT');
    });

    it('should return empty array when fetchFundingHistory not supported', async () => {
      mockExchange.has['fetchFundingHistory'] = false;

      const result = await connector.getFundingFees(['BTC/USDT:USDT'], new Date('2024-01-01'));

      expect(result).toEqual([]);

      // Reset for other tests
      mockExchange.has['fetchFundingHistory'] = true;
    });

    it('should handle errors for individual symbols gracefully', async () => {
      mockExchange.fetchFundingHistory.mockRejectedValue(new Error('API error'));

      const result = await connector.getFundingFees(['BTC/USDT:USDT'], new Date('2024-01-01'));

      expect(result).toEqual([]);
    });
  });

  describe('getEarnBalance', () => {
    it('should return earn balance from standard methods', async () => {
      mockExchange.fetchBalance.mockResolvedValue({
        USDT: { total: 1000 },
      } as unknown as ccxt.Balances);

      const result = await connector.getEarnBalance();

      expect(result.equity).toBeGreaterThanOrEqual(0);
      expect(result.available_margin).toBe(0);
    });

    it('should return zero when no earn balance found', async () => {
      mockExchange.fetchBalance.mockRejectedValue(new Error('Not available'));

      const result = await connector.getEarnBalance();

      expect(result.equity).toBe(0);
      expect(result.available_margin).toBe(0);
    });
  });

  describe('getTrades', () => {
    it('should return trades within date range', async () => {
      mockExchange.loadMarkets.mockResolvedValue({});
      mockExchange.markets = {
        'BTC/USDT': { spot: true },
      } as unknown as ccxt.Dictionary<ccxt.Market>;
      mockExchange.fetchClosedOrders.mockResolvedValue([
        { symbol: 'BTC/USDT' },
      ] as unknown as ccxt.Order[]);
      mockExchange.fetchMyTrades.mockResolvedValue([
        {
          id: 'trade1',
          symbol: 'BTC/USDT',
          side: 'buy',
          amount: 0.1,
          price: 50000,
          fee: { cost: 5, currency: 'USDT' },
          timestamp: new Date('2024-01-15').getTime(),
          order: 'order1',
          info: { realizedPnl: 100 },
        },
      ] as unknown as ccxt.Trade[]);

      const result = await connector.getTrades(new Date('2024-01-01'), new Date('2024-01-31'));

      expect(result.length).toBe(1);
      expect(result[0]!.symbol).toBe('BTC/USDT');
      expect(result[0]!.side).toBe('buy');
    });
  });
});
