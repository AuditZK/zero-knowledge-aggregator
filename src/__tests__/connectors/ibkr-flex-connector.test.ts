import { IbkrFlexConnector } from '../../connectors/IbkrFlexConnector';
import { IbkrFlexService, FlexTrade, FlexAccountSummary, FlexPosition } from '../../external/ibkr-flex-service';
import { ExchangeCredentials } from '../../types';

// Mock IbkrFlexService
jest.mock('../../external/ibkr-flex-service');

describe('IbkrFlexConnector', () => {
  let connector: IbkrFlexConnector;
  let mockFlexService: jest.Mocked<IbkrFlexService>;

  const mockCredentials: ExchangeCredentials = {
    userUid: 'user_test123',
    exchange: 'ibkr',
    label: 'IBKR Account',
    apiKey: 'flex_token_123',
    apiSecret: 'query_id_456',
  };

  const mockAccountSummary: FlexAccountSummary = {
    date: '2024-01-15',
    cash: 50000,
    netLiquidationValue: 150000,
    stockValue: 80000,
    optionValue: 15000,
    commodityValue: 5000,
    unrealizedPnL: 5000,
    realizedPnL: 2000,
  };

  const mockTrades: FlexTrade[] = [
    {
      tradeID: 'trade_1',
      symbol: 'AAPL',
      buySell: 'BUY',
      quantity: 100,
      tradePrice: 150,
      ibCommission: -1.5,
      ibCommissionCurrency: 'USD',
      tradeDate: '2024-01-15',
      tradeTime: '10:30:00',
      ibOrderID: 'order_1',
      fifoPnlRealized: 0,
      netCash: -15000,
      closePrice: 150,
      assetCategory: 'STK',
    },
    {
      tradeID: 'trade_2',
      symbol: 'SPY240315C500',
      buySell: 'BUY',
      quantity: 10,
      tradePrice: 5.5,
      ibCommission: -0.65,
      ibCommissionCurrency: 'USD',
      tradeDate: '2024-01-15',
      tradeTime: '11:00:00',
      ibOrderID: 'order_2',
      fifoPnlRealized: 0,
      netCash: -55,
      closePrice: 5.5,
      assetCategory: 'OPT',
    },
  ];

  const mockPositions: FlexPosition[] = [
    {
      symbol: 'AAPL',
      position: 100,
      costBasisPrice: 145,
      markPrice: 150,
      fifoPnlUnrealized: 500,
      positionValue: 15000,
      openPrice: 145,
    },
    {
      symbol: 'TSLA',
      position: -50,
      costBasisPrice: 200,
      markPrice: 195,
      fifoPnlUnrealized: 250,
      positionValue: -9750,
      openPrice: 200,
    },
  ];

  beforeEach(() => {
    mockFlexService = {
      getFlexDataCached: jest.fn(),
      parseAccountSummary: jest.fn(),
      parseTrades: jest.fn(),
      parsePositions: jest.fn(),
      testConnection: jest.fn(),
    } as unknown as jest.Mocked<IbkrFlexService>;

    connector = new IbkrFlexConnector(mockCredentials, mockFlexService);
  });

  describe('constructor', () => {
    it('should throw error when apiKey is missing', () => {
      const invalidCredentials = { ...mockCredentials, apiKey: '' };
      expect(() => new IbkrFlexConnector(invalidCredentials, mockFlexService)).toThrow(
        'IBKR Flex requires apiKey (token) and apiSecret (queryId)'
      );
    });

    it('should throw error when apiSecret is missing', () => {
      const invalidCredentials = { ...mockCredentials, apiSecret: '' };
      expect(() => new IbkrFlexConnector(invalidCredentials, mockFlexService)).toThrow(
        'IBKR Flex requires apiKey (token) and apiSecret (queryId)'
      );
    });

    it('should create connector with valid credentials', () => {
      expect(() => new IbkrFlexConnector(mockCredentials, mockFlexService)).not.toThrow();
    });
  });

  describe('getExchangeName', () => {
    it('should return ibkr', () => {
      expect(connector.getExchangeName()).toBe('ibkr');
    });
  });

  describe('supportsFeature', () => {
    it('should support positions feature', () => {
      expect(connector.supportsFeature('positions')).toBe(true);
    });

    it('should support trades feature', () => {
      expect(connector.supportsFeature('trades')).toBe(true);
    });

    it('should support historical_data feature', () => {
      expect(connector.supportsFeature('historical_data')).toBe(true);
    });

    it('should not support real_time feature', () => {
      expect(connector.supportsFeature('real_time')).toBe(false);
    });
  });

  describe('getBalance', () => {
    it('should throw error when no account data found', async () => {
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([]);

      await expect(connector.getBalance()).rejects.toThrow('No account data found in Flex report');
    });
  });

  describe('getBalanceBreakdown', () => {
    it('should return breakdown with all asset categories', async () => {
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([mockAccountSummary]);
      mockFlexService.parseTrades.mockResolvedValue(mockTrades);

      const result = await connector.getBalanceBreakdown();

      expect(result).toHaveProperty('global');
      expect(result).toHaveProperty('stocks');
      expect(result).toHaveProperty('options');
      expect(result).toHaveProperty('futures_commodities');
      expect(result).toHaveProperty('cfd');
      expect(result).toHaveProperty('forex');
    });

    it('should include trade metrics in breakdown', async () => {
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([mockAccountSummary]);
      mockFlexService.parseTrades.mockResolvedValue(mockTrades);

      const result = await connector.getBalanceBreakdown();

      expect(result.global!.equity).toBe(150000);
      expect(result.global!.available_margin).toBe(50000);
      expect(result.stocks!.equity).toBe(80000);
      expect(result.options!.equity).toBe(15000);
    });

    it('should calculate total trades and volume', async () => {
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([mockAccountSummary]);
      mockFlexService.parseTrades.mockResolvedValue(mockTrades);

      const result = await connector.getBalanceBreakdown();

      // Total trades = 2 (one stock, one option)
      expect(result.global!.trades).toBe(2);
    });
  });

  describe('getHistoricalSummaries', () => {
    it('should return historical data with breakdowns', async () => {
      const summaries = [
        { ...mockAccountSummary, date: '2024-01-14' },
        { ...mockAccountSummary, date: '2024-01-15' },
      ];
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue(summaries);
      mockFlexService.parseTrades.mockResolvedValue(mockTrades);

      const result = await connector.getHistoricalSummaries();

      expect(result.length).toBe(2);
      expect(result[0]!.date).toBe('2024-01-14');
      expect(result[0]!.breakdown).toBeDefined();
    });

    it('should return empty array when no summaries found', async () => {
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([]);
      mockFlexService.parseTrades.mockResolvedValue([]);

      const result = await connector.getHistoricalSummaries();

      expect(result).toEqual([]);
    });
  });

  describe('getCurrentPositions', () => {
    it('should return mapped positions with correct sides', async () => {
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parsePositions.mockResolvedValue(mockPositions);

      const result = await connector.getCurrentPositions();

      expect(result.length).toBe(2);

      // Long position
      const longPos = result.find(p => p.symbol === 'AAPL');
      expect(longPos).toBeDefined();
      expect(longPos!.side).toBe('long');
      expect(longPos!.size).toBe(100);

      // Short position
      const shortPos = result.find(p => p.symbol === 'TSLA');
      expect(shortPos).toBeDefined();
      expect(shortPos!.side).toBe('short');
      expect(shortPos!.size).toBe(50);
    });

    it('should include unrealized PnL', async () => {
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parsePositions.mockResolvedValue(mockPositions);

      const result = await connector.getCurrentPositions();

      const aaplPos = result.find(p => p.symbol === 'AAPL');
      expect(aaplPos!.unrealizedPnl).toBe(500);
    });
  });

  describe('getTrades', () => {
    it('should return trades within date range', async () => {
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseTrades.mockResolvedValue(mockTrades);

      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');
      const result = await connector.getTrades(startDate, endDate);

      expect(result.length).toBe(2);
      expect(result[0]!.symbol).toBe('AAPL');
      expect(result[0]!.side).toBe('buy');
    });

    it('should filter out trades outside date range', async () => {
      const tradesWithDates: FlexTrade[] = [
        { ...mockTrades[0], tradeDate: '2024-01-15' } as FlexTrade,
        { ...mockTrades[1], tradeDate: '2024-02-01' } as FlexTrade, // Outside range
      ];
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseTrades.mockResolvedValue(tradesWithDates);

      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');
      const result = await connector.getTrades(startDate, endDate);

      expect(result.length).toBe(1);
    });

    it('should map sell trades correctly', async () => {
      const sellTrade: FlexTrade = { ...mockTrades[0], buySell: 'SELL' } as FlexTrade;
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseTrades.mockResolvedValue([sellTrade]);

      const result = await connector.getTrades(new Date('2024-01-01'), new Date('2024-01-31'));

      expect(result[0]!.side).toBe('sell');
    });
  });

  describe('testConnection', () => {
    it('should return true for valid connection', async () => {
      mockFlexService.testConnection.mockResolvedValue(true);

      const result = await connector.testConnection();

      expect(result).toBe(true);
      expect(mockFlexService.testConnection).toHaveBeenCalledWith('flex_token_123', 'query_id_456');
    });

    it('should return false for invalid connection', async () => {
      mockFlexService.testConnection.mockResolvedValue(false);

      const result = await connector.testConnection();

      expect(result).toBe(false);
    });

    it('should return false when connection throws error', async () => {
      mockFlexService.testConnection.mockRejectedValue(new Error('Network error'));

      const result = await connector.testConnection();

      expect(result).toBe(false);
    });
  });

  describe('getFullFlexReport', () => {
    it('should return raw XML data', async () => {
      const xmlData = '<FlexQueryResponse>...</FlexQueryResponse>';
      mockFlexService.getFlexDataCached.mockResolvedValue(xmlData);

      const result = await connector.getFullFlexReport();

      expect(result).toBe(xmlData);
    });
  });

  describe('trade categorization', () => {
    const createTradeWithCategory = (category: string): FlexTrade => ({
      tradeID: 'trade_cat',
      symbol: 'TEST',
      buySell: 'BUY',
      quantity: 100,
      tradePrice: 100,
      ibCommission: -1,
      ibCommissionCurrency: 'USD',
      tradeDate: '2024-01-15',
      tradeTime: '10:00:00',
      ibOrderID: 'order_cat',
      fifoPnlRealized: 0,
      netCash: -10000,
      closePrice: 100,
      assetCategory: category,
    });

    it('should categorize STK trades as stocks', async () => {
      const stkTrade = createTradeWithCategory('STK');
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([mockAccountSummary]);
      mockFlexService.parseTrades.mockResolvedValue([stkTrade]);

      const result = await connector.getBalanceBreakdown();

      expect(result.stocks!.trades).toBe(1);
    });

    it('should categorize OPT trades as options', async () => {
      const optTrade = createTradeWithCategory('OPT');
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([mockAccountSummary]);
      mockFlexService.parseTrades.mockResolvedValue([optTrade]);

      const result = await connector.getBalanceBreakdown();

      expect(result.options!.trades).toBe(1);
    });

    it('should categorize FUT trades as futures_commodities', async () => {
      const futTrade = createTradeWithCategory('FUT');
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([mockAccountSummary]);
      mockFlexService.parseTrades.mockResolvedValue([futTrade]);

      const result = await connector.getBalanceBreakdown();

      expect(result.futures_commodities!.trades).toBe(1);
    });

    it('should categorize CMDTY trades as futures_commodities', async () => {
      const cmdtyTrade = createTradeWithCategory('CMDTY');
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([mockAccountSummary]);
      mockFlexService.parseTrades.mockResolvedValue([cmdtyTrade]);

      const result = await connector.getBalanceBreakdown();

      expect(result.futures_commodities!.trades).toBe(1);
    });

    it('should categorize CFD trades correctly', async () => {
      const cfdTrade = createTradeWithCategory('CFD');
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([mockAccountSummary]);
      mockFlexService.parseTrades.mockResolvedValue([cfdTrade]);

      const result = await connector.getBalanceBreakdown();

      expect(result.cfd!.trades).toBe(1);
    });

    it('should categorize CASH trades as forex', async () => {
      const forexTrade = createTradeWithCategory('CASH');
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([mockAccountSummary]);
      mockFlexService.parseTrades.mockResolvedValue([forexTrade]);

      const result = await connector.getBalanceBreakdown();

      expect(result.forex!.trades).toBe(1);
    });

    it('should default unknown categories to stocks', async () => {
      const unknownTrade = createTradeWithCategory('UNKNOWN');
      mockFlexService.getFlexDataCached.mockResolvedValue('<xml>data</xml>');
      mockFlexService.parseAccountSummary.mockResolvedValue([mockAccountSummary]);
      mockFlexService.parseTrades.mockResolvedValue([unknownTrade]);

      const result = await connector.getBalanceBreakdown();

      expect(result.stocks!.trades).toBe(1);
    });
  });
});
