import { CTraderConnector } from '../../connectors/CTraderConnector';
import { CTraderApiService, CTraderAccount, CTraderPosition, CTraderDeal, CTraderCashflow } from '../../external/ctrader-api-service';
import { ExchangeCredentials } from '../../types';

// Mock CTraderApiService
jest.mock('../../external/ctrader-api-service');

describe('CTraderConnector', () => {
  let connector: CTraderConnector;
  let mockApiService: jest.Mocked<CTraderApiService>;

  const mockCredentials: ExchangeCredentials = {
    userUid: 'user_test123',
    exchange: 'ctrader',
    label: 'cTrader Account',
    apiKey: 'test_access_token',
    apiSecret: 'test_refresh_token',
  };

  const createMockAccount = (id: number, isLive: boolean = true): CTraderAccount => ({
    ctidTraderAccountId: id,
    isLive,
    traderLogin: id,
    balance: 1000000,
    balanceVersion: 1,
    managerBonus: 0,
    ibBonus: 0,
    nonWithdrawableBonus: 0,
    depositAssetId: 1,
    swapFree: false,
    leverageInCents: 10000,
    brokerName: 'TestBroker',
    brokerTitle: 'Test Broker',
  });

  const createMockPosition = (
    symbolId: number,
    side: 'BUY' | 'SELL',
    volume: number,
    price: number,
    unrealizedPnl: number
  ): CTraderPosition => ({
    positionId: Math.floor(Math.random() * 10000),
    tradeData: {
      symbolId,
      volume: volume * 100, // In cents
      tradeSide: side,
      openTimestamp: Date.now(),
      guaranteedStopLoss: false,
      usedMargin: 50000,
    },
    positionStatus: 'POSITION_STATUS_OPEN',
    swap: 0,
    price: price * 100000, // In price cents (5 decimals)
    utcLastUpdateTimestamp: Date.now(),
    commission: 150,
    guaranteedStopLoss: false,
    usedMargin: 50000,
    moneyDigits: 2,
    unrealizedNetProfit: unrealizedPnl * 100, // In cents
  });

  const createMockDeal = (
    dealId: number,
    symbolId: number,
    side: 'BUY' | 'SELL',
    volume: number,
    execPrice: number,
    options: { closePositionDetail?: CTraderDeal['closePositionDetail'] } = {}
  ): CTraderDeal => ({
    dealId,
    orderId: dealId + 1000,
    positionId: dealId + 2000,
    volume: volume * 100,
    filledVolume: volume * 100,
    symbolId,
    createTimestamp: Date.now() - 60000,
    executionTimestamp: Date.now(),
    utcLastUpdateTimestamp: Date.now(),
    executionPrice: execPrice * 100000,
    tradeSide: side,
    dealStatus: 'FILLED',
    commission: 150,
    closePositionDetail: options.closePositionDetail,
  });

  beforeEach(() => {
    jest.clearAllMocks();

    mockApiService = {
      getAccounts: jest.fn(),
      setActiveAccount: jest.fn(),
      getIsLive: jest.fn().mockReturnValue(true),
      getTraderInfo: jest.fn(),
      getAccountBalance: jest.fn(),
      getPositions: jest.fn(),
      getDeals: jest.fn(),
      getSymbolName: jest.fn(),
      getSymbol: jest.fn(),
      getCashflows: jest.fn(),
      testConnection: jest.fn(),
      refreshToken: jest.fn(),
      disconnect: jest.fn(),
    } as unknown as jest.Mocked<CTraderApiService>;

    (CTraderApiService as jest.Mock).mockImplementation(() => mockApiService);

    connector = new CTraderConnector(mockCredentials);
  });

  describe('constructor', () => {
    it('should create connector with valid credentials', () => {
      expect(connector).toBeDefined();
      expect(connector.getExchangeName()).toBe('ctrader');
    });

    it('should throw error when apiKey is missing', () => {
      expect(() => new CTraderConnector({ ...mockCredentials, apiKey: '' }))
        .toThrow('cTrader requires apiKey (access_token from OAuth)');
    });
  });

  describe('getExchangeName', () => {
    it('should return ctrader', () => {
      expect(connector.getExchangeName()).toBe('ctrader');
    });
  });

  describe('detectIsPaper', () => {
    it('should return false for live account', async () => {
      mockApiService.getIsLive.mockReturnValue(true);
      expect(await connector.detectIsPaper()).toBe(false);
    });

    it('should return true for demo account', async () => {
      mockApiService.getIsLive.mockReturnValue(false);
      expect(await connector.detectIsPaper()).toBe(true);
    });
  });

  describe('getBalance', () => {
    it('should return balance data', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount(12345)]);
      mockApiService.getAccountBalance.mockResolvedValue({
        balance: 10000,
        equity: 10500,
        unrealizedPnl: 500,
        currency: 'USD',
        marginUsed: 2000,
        marginAvailable: 8500,
      });

      const result = await connector.getBalance();

      expect(result.balance).toBe(10000);
      expect(result.equity).toBe(10500);
      expect(result.unrealizedPnl).toBe(500);
      expect(result.currency).toBe('USD');
    });
  });

  describe('getCurrentPositions', () => {
    it('should return mapped positions', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount(12345)]);
      mockApiService.getPositions.mockResolvedValue([
        createMockPosition(1, 'BUY', 100, 1.1050, 250),
        createMockPosition(2, 'SELL', 50, 150.25, -100),
      ]);
      mockApiService.getSymbolName
        .mockResolvedValueOnce('EURUSD')
        .mockResolvedValueOnce('AAPL');

      const positions = await connector.getCurrentPositions();

      expect(positions).toHaveLength(2);
      expect(positions[0]!.symbol).toBe('EURUSD');
      expect(positions[0]!.side).toBe('long');
      expect(positions[1]!.symbol).toBe('AAPL');
      expect(positions[1]!.side).toBe('short');
    });

    it('should return empty array when no positions', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount(12345)]);
      mockApiService.getPositions.mockResolvedValue([]);

      const positions = await connector.getCurrentPositions();

      expect(positions).toEqual([]);
    });
  });

  describe('getTrades', () => {
    it('should return mapped trades from deals', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount(12345)]);
      mockApiService.getDeals.mockResolvedValue([
        createMockDeal(1001, 1, 'BUY', 100, 1.1050),
      ]);
      mockApiService.getSymbolName.mockResolvedValue('EURUSD');

      const trades = await connector.getTrades(new Date('2024-01-01'), new Date('2024-12-31'));

      expect(trades).toHaveLength(1);
      expect(trades[0]!.symbol).toBe('EURUSD');
      expect(trades[0]!.side).toBe('buy');
      expect(trades[0]!.quantity).toBe(100); // 10000 / 100
      expect(trades[0]!.fee).toBe(1.5); // 150 / 100
    });

    it('should filter out non-filled deals', async () => {
      const rejectedDeal = createMockDeal(1002, 1, 'SELL', 50, 1.1100);
      rejectedDeal.dealStatus = 'REJECTED';

      mockApiService.getAccounts.mockResolvedValue([createMockAccount(12345)]);
      mockApiService.getDeals.mockResolvedValue([
        createMockDeal(1001, 1, 'BUY', 100, 1.1050),
        rejectedDeal,
      ]);
      mockApiService.getSymbolName.mockResolvedValue('EURUSD');

      const trades = await connector.getTrades(new Date('2024-01-01'), new Date('2024-12-31'));

      expect(trades).toHaveLength(1);
    });

    it('should calculate realized PnL from closePositionDetail', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount(12345)]);
      mockApiService.getDeals.mockResolvedValue([
        createMockDeal(1001, 1, 'SELL', 100, 1.1100, {
          closePositionDetail: {
            entryPrice: 110500,
            grossProfit: 50000,
            swap: -500,
            commission: 150,
            balance: 1050000,
            balanceVersion: 5,
          },
        }),
      ]);
      mockApiService.getSymbolName.mockResolvedValue('EURUSD');

      const trades = await connector.getTrades(new Date('2024-01-01'), new Date('2024-12-31'));

      // realizedPnl = (grossProfit - commission - swap) / 100
      // = (50000 - 150 - (-500)) / 100 = 50350 / 100 = 503.5
      expect(trades[0]!.realizedPnl).toBe(503.5);
    });

    it('should return empty array when no deals', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount(12345)]);
      mockApiService.getDeals.mockResolvedValue([]);

      const trades = await connector.getTrades(new Date('2024-01-01'), new Date('2024-12-31'));

      expect(trades).toEqual([]);
    });
  });

  describe('testConnection', () => {
    it('should return true for successful connection', async () => {
      mockApiService.testConnection.mockResolvedValue(true);
      expect(await connector.testConnection()).toBe(true);
    });

    it('should return false for failed connection', async () => {
      mockApiService.testConnection.mockResolvedValue(false);
      expect(await connector.testConnection()).toBe(false);
    });

    it('should return false on error', async () => {
      mockApiService.testConnection.mockRejectedValue(new Error('Network error'));
      expect(await connector.testConnection()).toBe(false);
    });
  });

  describe('getCashflows', () => {
    it('should return deposits and withdrawals', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount(12345)]);
      mockApiService.getCashflows.mockResolvedValue([
        { id: 1, type: 'DEPOSIT', amount: 500000, timestamp: Date.now() },
        { id: 2, type: 'DEPOSIT', amount: 200000, timestamp: Date.now() },
        { id: 3, type: 'WITHDRAW', amount: 100000, timestamp: Date.now() },
      ] as CTraderCashflow[]);

      const result = await connector.getCashflows(new Date('2024-01-01'));

      expect(result.deposits).toBe(7000); // (500000 + 200000) / 100
      expect(result.withdrawals).toBe(1000); // 100000 / 100
    });

    it('should return zeros when no cashflows', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount(12345)]);
      mockApiService.getCashflows.mockResolvedValue([]);

      const result = await connector.getCashflows(new Date('2024-01-01'));

      expect(result.deposits).toBe(0);
      expect(result.withdrawals).toBe(0);
    });
  });

  describe('getAccounts', () => {
    it('should return account list', async () => {
      mockApiService.getAccounts.mockResolvedValue([
        createMockAccount(12345, true),
        createMockAccount(67890, false),
      ]);

      const accounts = await connector.getAccounts();

      expect(accounts).toHaveLength(2);
      expect(accounts[0]!.id).toBe(12345);
      expect(accounts[0]!.isLive).toBe(true);
      expect(accounts[1]!.id).toBe(67890);
      expect(accounts[1]!.isLive).toBe(false);
    });
  });

  describe('switchAccount', () => {
    it('should switch to existing account', async () => {
      mockApiService.getAccounts.mockResolvedValue([
        createMockAccount(12345),
        createMockAccount(67890),
      ]);

      await connector.switchAccount(67890);

      expect(mockApiService.setActiveAccount).toHaveBeenCalledWith(67890);
    });

    it('should throw when account not found', async () => {
      mockApiService.getAccounts.mockResolvedValue([createMockAccount(12345)]);

      await expect(connector.switchAccount(99999)).rejects.toThrow('Account 99999 not found');
    });
  });
});
