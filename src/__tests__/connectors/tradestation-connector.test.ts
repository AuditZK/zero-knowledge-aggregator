import { TradeStationConnector } from '../../connectors/TradeStationConnector';
import { TradeStationApiService, TradeStationAccount, TradeStationCashflow } from '../../external/tradestation-api-service';
import { ExchangeCredentials } from '../../types';

// Mock TradeStationApiService
jest.mock('../../external/tradestation-api-service');

describe('TradeStationConnector', () => {
  let connector: TradeStationConnector;
  let mockApiService: jest.Mocked<TradeStationApiService>;

  const mockCredentials: ExchangeCredentials = {
    userUid: 'user_test123',
    exchange: 'tradestation',
    label: 'TradeStation Account',
    apiKey: 'client_id_123',
    apiSecret: 'client_secret_456',
    passphrase: 'refresh_token_789',
  };

  const createMockAccount = (accountId: string): TradeStationAccount => ({
    AccountID: accountId,
    AccountType: 'Cash',
    Alias: `Account ${accountId}`,
    Currency: 'USD',
    Status: 'Active',
    StatusDescription: 'Active account',
  });

  const createMockCashflow = (type: 'deposit' | 'withdrawal', amount: number): TradeStationCashflow => ({
    id: `cf_${Date.now()}`,
    type,
    amount,
    date: new Date(),
    description: `${type} transaction`,
  });

  const createMockPosition = (
    symbol: string,
    longShort: 'Long' | 'Short',
    quantity: number,
    avgPrice: number,
    last: number,
    unrealizedPnl: number
  ) => ({
    AccountID: 'ACC001',
    Symbol: symbol,
    Quantity: quantity,
    AveragePrice: avgPrice,
    Last: last,
    Bid: last - 0.01,
    Ask: last + 0.01,
    MarketValue: Math.abs(quantity) * last,
    TodaysProfitLoss: unrealizedPnl * 0.5,
    UnrealizedProfitLoss: unrealizedPnl,
    UnrealizedProfitLossPercent: (unrealizedPnl / (Math.abs(quantity) * avgPrice)) * 100,
    UnrealizedProfitLossQty: unrealizedPnl / Math.abs(quantity),
    LongShort: longShort,
    AssetType: 'Stock',
  });

  const createMockLeg = (symbol: string, side: 'Buy' | 'Sell', execQty: number, execPrice: number) => ({
    BuyOrSell: side,
    Quantity: execQty,
    ExecQuantity: execQty,
    ExecPrice: execPrice,
    Symbol: symbol,
    AssetType: 'Stock',
  });

  const createMockOrder = (
    orderId: string,
    symbol: string,
    status: string,
    legs: ReturnType<typeof createMockLeg>[],
    options: {
      closedDateTime?: string;
      openedDateTime?: string;
      filledPrice?: number;
      filledQuantity?: number;
      commission?: number;
      routingFee?: number;
    } = {}
  ) => ({
    AccountID: 'ACC001',
    OrderID: orderId,
    Symbol: symbol,
    Type: 'Market',
    Status: status,
    StatusDescription: `${status} order`,
    OpenedDateTime: options.openedDateTime || '2024-01-15T10:00:00Z',
    ClosedDateTime: options.closedDateTime,
    FilledPrice: options.filledPrice,
    FilledQuantity: options.filledQuantity,
    OrderedQuantity: legs.reduce((sum, l) => sum + l.Quantity, 0) || options.filledQuantity || 0,
    Duration: 'Day',
    Legs: legs,
    Commission: options.commission,
    RoutingFee: options.routingFee,
  });

  beforeEach(() => {
    jest.clearAllMocks();

    mockApiService = {
      getAccounts: jest.fn(),
      getAggregatedBalance: jest.fn(),
      getPositions: jest.fn(),
      getHistoricalOrders: jest.fn(),
      testConnection: jest.fn(),
      getCashflows: jest.fn(),
    } as unknown as jest.Mocked<TradeStationApiService>;

    (TradeStationApiService as jest.Mock).mockImplementation(() => mockApiService);

    connector = new TradeStationConnector(mockCredentials);
  });

  describe('constructor', () => {
    it('should create connector with valid credentials', () => {
      expect(connector).toBeDefined();
      expect(connector.getExchangeName()).toBe('tradestation');
    });

    it('should throw error when apiKey is missing', () => {
      const invalidCredentials = { ...mockCredentials, apiKey: '' };
      expect(() => new TradeStationConnector(invalidCredentials)).toThrow(
        'TradeStation requires apiKey (client_id), apiSecret (client_secret), and passphrase (refresh_token)'
      );
    });

    it('should throw error when apiSecret is missing', () => {
      const invalidCredentials = { ...mockCredentials, apiSecret: '' };
      expect(() => new TradeStationConnector(invalidCredentials)).toThrow(
        'TradeStation requires apiKey (client_id), apiSecret (client_secret), and passphrase (refresh_token)'
      );
    });

    it('should throw error when passphrase is missing', () => {
      const invalidCredentials = { ...mockCredentials, passphrase: '' };
      expect(() => new TradeStationConnector(invalidCredentials)).toThrow(
        'TradeStation requires apiKey (client_id), apiSecret (client_secret), and passphrase (refresh_token)'
      );
    });
  });

  describe('getExchangeName', () => {
    it('should return tradestation', () => {
      expect(connector.getExchangeName()).toBe('tradestation');
    });
  });

  describe('getBalance', () => {
    it('should return aggregated balance', async () => {
      mockApiService.getAggregatedBalance.mockResolvedValue({
        totalCash: 50000,
        totalEquity: 100000,
        totalUnrealizedPnl: 5000,
        currency: 'USD',
        accounts: [createMockAccount('ACC001'), createMockAccount('ACC002')],
      });

      const result = await connector.getBalance();

      expect(result.balance).toBe(50000);
      expect(result.equity).toBe(100000);
      expect(result.currency).toBe('USD');
    });

    it('should throw error when balance fetch fails', async () => {
      mockApiService.getAggregatedBalance.mockResolvedValue(null as never);

      await expect(connector.getBalance()).rejects.toThrow('Failed to fetch TradeStation account info');
    });
  });

  describe('getCurrentPositions', () => {
    it('should return positions with correct mapping', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount('ACC001')]);
      mockApiService.getPositions.mockResolvedValue([
        createMockPosition('AAPL', 'Long', 100, 150, 155, 500),
        createMockPosition('TSLA', 'Short', -50, 200, 195, 250),
      ]);

      const result = await connector.getCurrentPositions();

      expect(result.length).toBe(2);
      expect(result[0]!.symbol).toBe('AAPL');
      expect(result[0]!.side).toBe('long');
      expect(result[0]!.size).toBe(100);
      expect(result[0]!.entryPrice).toBe(150);
      expect(result[0]!.markPrice).toBe(155);
      expect(result[0]!.unrealizedPnl).toBe(500);

      expect(result[1]!.symbol).toBe('TSLA');
      expect(result[1]!.side).toBe('short');
      expect(result[1]!.size).toBe(50);
    });
  });

  describe('getTrades', () => {
    it('should return trades from filled orders', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount('ACC001')]);
      mockApiService.getHistoricalOrders.mockResolvedValue([
        createMockOrder('ORD001', 'AAPL', 'Filled', [createMockLeg('AAPL', 'Buy', 100, 150)], {
          closedDateTime: '2024-01-15T10:30:00Z',
          filledPrice: 150,
          filledQuantity: 100,
          commission: 1.5,
          routingFee: 0.5,
        }),
      ]);

      const result = await connector.getTrades(new Date('2024-01-01'), new Date('2024-01-31'));

      expect(result.length).toBe(1);
      expect(result[0]!.symbol).toBe('AAPL');
      expect(result[0]!.side).toBe('buy');
      expect(result[0]!.quantity).toBe(100);
      expect(result[0]!.price).toBe(150);
      expect(result[0]!.fee).toBe(2); // Commission + RoutingFee
    });

    it('should filter out orders outside date range', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount('ACC001')]);
      mockApiService.getHistoricalOrders.mockResolvedValue([
        createMockOrder('ORD001', 'AAPL', 'Filled', [createMockLeg('AAPL', 'Buy', 100, 150)], {
          closedDateTime: '2024-01-15T10:30:00Z',
        }),
        createMockOrder('ORD002', 'MSFT', 'Filled', [createMockLeg('MSFT', 'Buy', 50, 400)], {
          closedDateTime: '2024-02-15T10:30:00Z', // Outside range
          openedDateTime: '2024-02-15T10:00:00Z',
        }),
      ]);

      const result = await connector.getTrades(new Date('2024-01-01'), new Date('2024-01-31'));

      expect(result.length).toBe(1);
      expect(result[0]!.symbol).toBe('AAPL');
    });

    it('should filter out non-filled orders', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount('ACC001')]);
      mockApiService.getHistoricalOrders.mockResolvedValue([
        createMockOrder('ORD001', 'AAPL', 'Filled', [createMockLeg('AAPL', 'Buy', 100, 150)], {
          closedDateTime: '2024-01-15T10:30:00Z',
        }),
        createMockOrder('ORD002', 'MSFT', 'Cancelled', [], {
          closedDateTime: '2024-01-15T10:30:00Z',
        }),
      ]);

      const result = await connector.getTrades(new Date('2024-01-01'), new Date('2024-01-31'));

      expect(result.length).toBe(1);
      expect(result[0]!.symbol).toBe('AAPL');
    });

    it('should handle FLL status as filled', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount('ACC001')]);
      mockApiService.getHistoricalOrders.mockResolvedValue([
        createMockOrder('ORD001', 'AAPL', 'FLL', [createMockLeg('AAPL', 'Sell', 100, 155)], {
          closedDateTime: '2024-01-15T10:30:00Z',
        }),
      ]);

      const result = await connector.getTrades(new Date('2024-01-01'), new Date('2024-01-31'));

      expect(result.length).toBe(1);
      expect(result[0]!.side).toBe('sell');
    });

    it('should use order-level data when no legs executed', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount('ACC001')]);
      mockApiService.getHistoricalOrders.mockResolvedValue([
        createMockOrder('ORD001', 'AAPL', 'Filled', [createMockLeg('AAPL', 'Buy', 0, 0)], {
          closedDateTime: '2024-01-15T10:30:00Z',
          filledPrice: 150,
          filledQuantity: 100,
          commission: 1,
        }),
      ]);

      const result = await connector.getTrades(new Date('2024-01-01'), new Date('2024-01-31'));

      expect(result.length).toBe(1);
      expect(result[0]!.quantity).toBe(100);
      expect(result[0]!.price).toBe(150);
    });
  });

  describe('testConnection', () => {
    it('should return true for successful connection', async () => {
      mockApiService.testConnection.mockResolvedValue(true);

      const result = await connector.testConnection();

      expect(result).toBe(true);
    });

    it('should return false for failed connection', async () => {
      mockApiService.testConnection.mockResolvedValue(false);

      const result = await connector.testConnection();

      expect(result).toBe(false);
    });

    it('should return false when connection throws error', async () => {
      mockApiService.testConnection.mockRejectedValue(new Error('Network error'));

      const result = await connector.testConnection();

      expect(result).toBe(false);
    });
  });

  describe('getCashflows', () => {
    it('should return deposits and withdrawals', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount('ACC001')]);
      mockApiService.getCashflows.mockResolvedValue([
        createMockCashflow('deposit', 10000),
        createMockCashflow('deposit', 5000),
        createMockCashflow('withdrawal', 2000),
      ]);

      const result = await connector.getCashflows(new Date('2024-01-01'));

      expect(result.deposits).toBe(15000);
      expect(result.withdrawals).toBe(2000);
    });

    it('should return zeros when no cashflows', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount('ACC001')]);
      mockApiService.getCashflows.mockResolvedValue([]);

      const result = await connector.getCashflows(new Date('2024-01-01'));

      expect(result.deposits).toBe(0);
      expect(result.withdrawals).toBe(0);
    });
  });

  describe('getAccountIds', () => {
    it('should return account IDs', async () => {
      mockApiService.getAccounts.mockResolvedValue([
        createMockAccount('ACC001'),
        createMockAccount('ACC002'),
      ]);

      const result = await connector.getAccountIds();

      expect(result).toEqual(['ACC001', 'ACC002']);
    });

    it('should throw error when no accounts found', async () => {
      mockApiService.getAccounts.mockResolvedValue([]);

      await expect(connector.getAccountIds()).rejects.toThrow('No TradeStation accounts found');
    });
  });
});
