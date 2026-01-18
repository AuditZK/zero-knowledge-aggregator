import { AlpacaConnector } from '../../connectors/AlpacaConnector';
import { AlpacaApiService } from '../../external/alpaca-api-service';
import type { ExchangeCredentials } from '../../types';

// Mock the AlpacaApiService
jest.mock('../../external/alpaca-api-service');

describe('AlpacaConnector', () => {
  let connector: AlpacaConnector;
  let mockApiService: jest.Mocked<AlpacaApiService>;

  const mockCredentials: ExchangeCredentials = {
    userUid: 'user_test123456789',
    exchange: 'alpaca',
    label: 'Test Account',
    apiKey: 'PKTEST123456789',
    apiSecret: 'secretkey123456789',
  };

  beforeEach(() => {
    jest.clearAllMocks();

    // Create mock instance
    mockApiService = {
      testConnection: jest.fn(),
      getAccountInfo: jest.fn(),
      getCurrentPositions: jest.fn(),
      getTradeHistory: jest.fn(),
      getCashflows: jest.fn(),
    } as unknown as jest.Mocked<AlpacaApiService>;

    // Mock the constructor
    (AlpacaApiService as jest.MockedClass<typeof AlpacaApiService>).mockImplementation(
      () => mockApiService
    );

    connector = new AlpacaConnector(mockCredentials);
  });

  describe('constructor', () => {
    it('should throw error if apiKey is missing', () => {
      expect(() => new AlpacaConnector({
        ...mockCredentials,
        apiKey: '',
      })).toThrow('Alpaca requires apiKey and apiSecret');
    });

    it('should throw error if apiSecret is missing', () => {
      expect(() => new AlpacaConnector({
        ...mockCredentials,
        apiSecret: '',
      })).toThrow('Alpaca requires apiKey and apiSecret');
    });
  });

  describe('getExchangeName', () => {
    it('should return alpaca', () => {
      expect(connector.getExchangeName()).toBe('alpaca');
    });
  });

  describe('getBalance', () => {
    it('should return balance data from account info', async () => {
      mockApiService.getAccountInfo.mockResolvedValue({
        id: 'acc123',
        account_number: '123456',
        status: 'ACTIVE',
        currency: 'USD',
        buying_power: '10000',
        regt_buying_power: '10000',
        daytrading_buying_power: '40000',
        cash: '5000.50',
        portfolio_value: '15000.75',
        pattern_day_trader: false,
        trading_blocked: false,
        transfers_blocked: false,
        account_blocked: false,
        created_at: '2020-01-01',
        trade_suspended_by_user: false,
        multiplier: '4',
        shorting_enabled: true,
        equity: '15000.75',
        last_equity: '14500',
        long_market_value: '10000',
        short_market_value: '0',
        initial_margin: '5000',
        maintenance_margin: '3000',
        last_maintenance_margin: '3000',
        sma: '10000',
        daytrade_count: 0,
      });

      const balance = await connector.getBalance();

      expect(balance.balance).toBe(5000.5);
      expect(balance.equity).toBe(15000.75);
      expect(balance.currency).toBe('USD');
    });

    it('should throw error when account info is null', async () => {
      mockApiService.getAccountInfo.mockResolvedValue(null);

      await expect(connector.getBalance()).rejects.toThrow(
        'Failed to fetch Alpaca account info'
      );
    });
  });

  describe('getCurrentPositions', () => {
    it('should return mapped positions', async () => {
      mockApiService.getCurrentPositions.mockResolvedValue([
        {
          symbol: 'AAPL',
          qty: '10',
          side: 'long',
          market_value: '1750.00',
          cost_basis: '1500.00',
          unrealized_pl: '250.00',
          unrealized_plpc: '0.1667',
          current_price: '175.00',
          lastday_price: '173.00',
          change_today: '0.0116',
          avg_entry_price: '150.00',
          asset_class: 'us_equity',
        },
        {
          symbol: 'MSFT',
          qty: '-5',
          side: 'short',
          market_value: '-2000.00',
          cost_basis: '-2100.00',
          unrealized_pl: '100.00',
          unrealized_plpc: '0.0476',
          current_price: '400.00',
          lastday_price: '398.00',
          change_today: '0.005',
          avg_entry_price: '420.00',
          asset_class: 'us_equity',
        },
      ]);

      const positions = await connector.getCurrentPositions();

      expect(positions).toHaveLength(2);
      const firstPos = positions[0];
      const secondPos = positions[1];
      expect(firstPos).toBeDefined();
      expect(secondPos).toBeDefined();
      expect(firstPos).toMatchObject({
        symbol: 'AAPL',
        side: 'long',
        size: 10,
        entryPrice: 150,
        markPrice: 175,
        unrealizedPnl: 250,
      });
      expect(secondPos).toMatchObject({
        symbol: 'MSFT',
        side: 'short',
        size: -5, // Negative for short position
      });
    });

    it('should return empty array when no positions', async () => {
      mockApiService.getCurrentPositions.mockResolvedValue([]);

      const positions = await connector.getCurrentPositions();

      expect(positions).toEqual([]);
    });
  });

  describe('getTrades', () => {
    it('should return filtered trades within date range', async () => {
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');

      mockApiService.getTradeHistory.mockResolvedValue([
        {
          id: 'trade1',
          activity_type: 'FILL',
          transaction_time: '2024-01-15T10:00:00Z',
          type: 'fill',
          price: '150.00',
          qty: '10',
          side: 'buy',
          symbol: 'AAPL',
          leaves_qty: '0',
          order_id: 'order123',
          cum_qty: '10',
          order_status: 'filled',
          net_amount: '-1500.00',
        },
        {
          id: 'trade2',
          activity_type: 'FILL',
          transaction_time: '2024-01-20T14:30:00Z',
          type: 'fill',
          price: '155.00',
          qty: '5',
          side: 'sell',
          symbol: 'AAPL',
          leaves_qty: '0',
          order_id: 'order124',
          cum_qty: '5',
          order_status: 'filled',
          net_amount: '775.00',
        },
      ]);

      const trades = await connector.getTrades(startDate, endDate);

      expect(trades).toHaveLength(2);
      expect(trades[0]).toMatchObject({
        symbol: 'AAPL',
        side: 'buy',
        quantity: 10,
        price: 150,
      });
      expect(trades[1]).toMatchObject({
        symbol: 'AAPL',
        side: 'sell',
        quantity: 5,
        price: 155,
      });
    });

    it('should filter out trades outside date range', async () => {
      const startDate = new Date('2024-01-15');
      const endDate = new Date('2024-01-20');

      mockApiService.getTradeHistory.mockResolvedValue([
        {
          id: 'trade1',
          activity_type: 'FILL',
          transaction_time: '2024-01-10T10:00:00Z', // Before start
          type: 'fill',
          price: '150.00',
          qty: '10',
          side: 'buy',
          symbol: 'AAPL',
          leaves_qty: '0',
          order_id: 'order123',
          cum_qty: '10',
          order_status: 'filled',
        },
        {
          id: 'trade2',
          activity_type: 'FILL',
          transaction_time: '2024-01-17T14:30:00Z', // Within range
          type: 'fill',
          price: '155.00',
          qty: '5',
          side: 'sell',
          symbol: 'AAPL',
          leaves_qty: '0',
          order_id: 'order124',
          cum_qty: '5',
          order_status: 'filled',
        },
      ]);

      const trades = await connector.getTrades(startDate, endDate);

      expect(trades).toHaveLength(1);
      expect(trades[0]?.symbol).toBe('AAPL');
    });
  });

  describe('testConnection', () => {
    it('should return true when connection succeeds', async () => {
      mockApiService.testConnection.mockResolvedValue(true);

      const result = await connector.testConnection();

      expect(result).toBe(true);
    });

    it('should return false when connection fails', async () => {
      mockApiService.testConnection.mockResolvedValue(false);

      const result = await connector.testConnection();

      expect(result).toBe(false);
    });

    it('should return false when connection throws', async () => {
      mockApiService.testConnection.mockRejectedValue(new Error('Network error'));

      const result = await connector.testConnection();

      expect(result).toBe(false);
    });
  });

  describe('getCashflows', () => {
    it('should return deposits and withdrawals', async () => {
      const since = new Date('2024-01-01');

      mockApiService.getCashflows.mockResolvedValue([
        {
          id: 'cf1',
          type: 'deposit',
          amount: 5000,
          date: new Date('2024-01-05'),
          status: 'completed',
        },
        {
          id: 'cf2',
          type: 'withdrawal',
          amount: 1000,
          date: new Date('2024-01-15'),
          status: 'completed',
        },
      ]);

      const result = await connector.getCashflows(since);

      expect(result.deposits).toBe(5000);
      expect(result.withdrawals).toBe(1000);
    });

    it('should return zeros when no cashflows', async () => {
      mockApiService.getCashflows.mockResolvedValue([]);

      const result = await connector.getCashflows(new Date());

      expect(result.deposits).toBe(0);
      expect(result.withdrawals).toBe(0);
    });
  });
});
