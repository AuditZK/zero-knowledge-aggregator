import { AlpacaApiService } from '../../external/alpaca-api-service';
import type { ExchangeCredentials } from '../../types';

// Mock the Alpaca SDK
jest.mock('@alpacahq/alpaca-trade-api', () => {
  return jest.fn().mockImplementation(() => ({
    getAccount: jest.fn(),
    getPositions: jest.fn(),
    getAccountActivities: jest.fn(),
  }));
});

import Alpaca from '@alpacahq/alpaca-trade-api';

describe('AlpacaApiService', () => {
  let service: AlpacaApiService;
  let mockAlpacaInstance: {
    getAccount: jest.Mock;
    getPositions: jest.Mock;
    getAccountActivities: jest.Mock;
  };

  const mockCredentials: ExchangeCredentials = {
    userUid: 'user_test123',
    exchange: 'alpaca',
    label: 'Test Account',
    apiKey: 'PKTEST123456789', // Paper trading key
    apiSecret: 'secretkey123456789',
  };

  const mockLiveCredentials: ExchangeCredentials = {
    ...mockCredentials,
    apiKey: 'AKTEST123456789', // Live key (doesn't start with PK)
  };

  beforeEach(() => {
    jest.clearAllMocks();

    mockAlpacaInstance = {
      getAccount: jest.fn(),
      getPositions: jest.fn(),
      getAccountActivities: jest.fn(),
    };

    (Alpaca as jest.MockedClass<typeof Alpaca>).mockImplementation(() => mockAlpacaInstance as any);
  });

  describe('constructor', () => {
    it('should detect paper trading from API key prefix', () => {
      service = new AlpacaApiService(mockCredentials);

      expect(Alpaca).toHaveBeenCalledWith(expect.objectContaining({
        paper: true,
        baseUrl: 'https://paper-api.alpaca.markets',
      }));
    });

    it('should detect live trading from API key prefix', () => {
      service = new AlpacaApiService(mockLiveCredentials);

      expect(Alpaca).toHaveBeenCalledWith(expect.objectContaining({
        paper: false,
        baseUrl: 'https://api.alpaca.markets',
      }));
    });

    it('should pass credentials to Alpaca SDK', () => {
      service = new AlpacaApiService(mockCredentials);

      expect(Alpaca).toHaveBeenCalledWith(expect.objectContaining({
        keyId: mockCredentials.apiKey,
        secretKey: mockCredentials.apiSecret,
      }));
    });
  });

  describe('testConnection', () => {
    beforeEach(() => {
      service = new AlpacaApiService(mockCredentials);
    });

    it('should return true when account fetches successfully', async () => {
      mockAlpacaInstance.getAccount.mockResolvedValue({
        id: 'acc123',
        status: 'ACTIVE',
      });

      const result = await service.testConnection();

      expect(result).toBe(true);
      expect(mockAlpacaInstance.getAccount).toHaveBeenCalled();
    });

    it('should return false when account fetch fails', async () => {
      mockAlpacaInstance.getAccount.mockRejectedValue(new Error('Unauthorized'));

      const result = await service.testConnection();

      expect(result).toBe(false);
    });
  });

  describe('getCurrentPositions', () => {
    beforeEach(() => {
      service = new AlpacaApiService(mockCredentials);
    });

    it('should return mapped positions', async () => {
      mockAlpacaInstance.getPositions.mockResolvedValue([
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
        },
      ]);

      const positions = await service.getCurrentPositions();

      expect(positions).toHaveLength(1);
      expect(positions[0]).toMatchObject({
        symbol: 'AAPL',
        qty: '10',
        side: 'long',
        market_value: '1750.00',
        current_price: '175.00',
      });
    });

    it('should return empty array when no positions', async () => {
      mockAlpacaInstance.getPositions.mockResolvedValue([]);

      const positions = await service.getCurrentPositions();

      expect(positions).toEqual([]);
    });

    it('should return empty array when fetch fails', async () => {
      mockAlpacaInstance.getPositions.mockRejectedValue(new Error('API error'));

      const positions = await service.getCurrentPositions();

      expect(positions).toEqual([]);
    });

    it('should handle missing optional fields', async () => {
      mockAlpacaInstance.getPositions.mockResolvedValue([
        {
          symbol: 'TSLA',
          qty: '5',
          side: 'long',
          market_value: '500.00',
          cost_basis: '450.00',
          unrealized_pl: '50.00',
          unrealized_plpc: '0.11',
          current_price: '100.00',
          // Missing lastday_price and change_today
        },
      ]);

      const positions = await service.getCurrentPositions();

      expect(positions).toHaveLength(1);
      expect(positions[0]?.lastday_price).toBe('0');
      expect(positions[0]?.change_today).toBe('0');
    });
  });

  describe('getTradeHistory', () => {
    beforeEach(() => {
      service = new AlpacaApiService(mockCredentials);
    });

    it('should fetch trade activities with date range', async () => {
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');

      mockAlpacaInstance.getAccountActivities.mockResolvedValue([
        {
          id: 'activity1',
          activity_type: 'FILL',
          transaction_time: '2024-01-15T10:00:00Z',
          type: 'fill',
          price: '150.00',
          qty: '10',
          side: 'buy',
          symbol: 'AAPL',
        },
      ]);

      const trades = await service.getTradeHistory(startDate, endDate);

      expect(trades).toHaveLength(1);
      expect(mockAlpacaInstance.getAccountActivities).toHaveBeenCalledWith(
        expect.objectContaining({
          activityTypes: 'FILL',
          after: startDate.toISOString(),
          until: endDate.toISOString(),
        })
      );
    });

    it('should default to 90 days if no start date provided', async () => {
      mockAlpacaInstance.getAccountActivities.mockResolvedValue([]);

      await service.getTradeHistory();

      expect(mockAlpacaInstance.getAccountActivities).toHaveBeenCalledWith(
        expect.objectContaining({
          activityTypes: 'FILL',
        })
      );
    });

    it('should return empty array on error', async () => {
      mockAlpacaInstance.getAccountActivities.mockRejectedValue(new Error('API error'));

      const trades = await service.getTradeHistory();

      expect(trades).toEqual([]);
    });

    it('should map activity fields correctly', async () => {
      mockAlpacaInstance.getAccountActivities.mockResolvedValue([
        {
          id: 'activity1',
          activity_type: 'FILL',
          transaction_time: '2024-01-15T10:00:00Z',
          price: '150.00',
          qty: '10',
          side: 'buy',
          symbol: 'AAPL',
          leaves_qty: '0',
          order_id: 'order123',
          cum_qty: '10',
          order_status: 'filled',
        },
      ]);

      const trades = await service.getTradeHistory(new Date('2024-01-01'));

      expect(trades[0]).toMatchObject({
        id: 'activity1',
        symbol: 'AAPL',
        side: 'buy',
        price: '150.00',
        qty: '10',
      });
    });

    it('should handle activities with missing optional fields', async () => {
      mockAlpacaInstance.getAccountActivities.mockResolvedValue([
        {
          id: 'activity1',
          activity_type: 'FILL',
          transaction_time: '2024-01-15T10:00:00Z',
          // Missing most optional fields
        },
      ]);

      const trades = await service.getTradeHistory(new Date('2024-01-01'));

      expect(trades[0]).toMatchObject({
        id: 'activity1',
        type: '',
        price: '0',
        qty: '0',
        symbol: '',
      });
    });
  });

  describe('getCashflows', () => {
    beforeEach(() => {
      service = new AlpacaApiService(mockCredentials);
    });

    it('should fetch deposits and withdrawals', async () => {
      const since = new Date('2024-01-01');

      mockAlpacaInstance.getAccountActivities.mockResolvedValue([
        {
          id: 'cf1',
          activity_type: 'CSD', // Cash deposit
          transaction_time: '2024-01-05T10:00:00Z',
          net_amount: '5000.00',
          status: 'completed',
        },
        {
          id: 'cf2',
          activity_type: 'CSW', // Cash withdrawal
          transaction_time: '2024-01-10T10:00:00Z',
          net_amount: '-1000.00',
          status: 'completed',
        },
      ]);

      const cashflows = await service.getCashflows(since);

      expect(cashflows).toHaveLength(2);
      expect(cashflows[0]).toMatchObject({
        id: 'cf1',
        type: 'deposit',
        amount: 5000,
      });
      expect(cashflows[1]).toMatchObject({
        id: 'cf2',
        type: 'withdrawal',
        amount: 1000,
      });
    });

    it('should return empty array on error', async () => {
      mockAlpacaInstance.getAccountActivities.mockRejectedValue(new Error('API error'));

      const cashflows = await service.getCashflows(new Date());

      expect(cashflows).toEqual([]);
    });

    it('should request correct activity types', async () => {
      mockAlpacaInstance.getAccountActivities.mockResolvedValue([]);

      await service.getCashflows(new Date('2024-01-01'));

      expect(mockAlpacaInstance.getAccountActivities).toHaveBeenCalledWith(
        expect.objectContaining({
          activityTypes: 'CSD,CSW',
        })
      );
    });
  });

  describe('getAccountInfo', () => {
    beforeEach(() => {
      service = new AlpacaApiService(mockCredentials);
    });

    it('should return account information', async () => {
      mockAlpacaInstance.getAccount.mockResolvedValue({
        id: 'acc123',
        account_number: '123456',
        status: 'ACTIVE',
        currency: 'USD',
        buying_power: '10000',
        cash: '5000',
        portfolio_value: '15000',
        pattern_day_trader: false,
        trading_blocked: false,
        transfers_blocked: false,
        account_blocked: false,
        created_at: '2020-01-01',
        trade_suspended_by_user: false,
      });

      const account = await service.getAccountInfo();

      expect(account).not.toBeNull();
      expect(account?.id).toBe('acc123');
      expect(account?.status).toBe('ACTIVE');
      expect(account?.currency).toBe('USD');
      expect(account?.cash).toBe('5000');
      expect(account?.portfolio_value).toBe('15000');
    });

    it('should return null on error', async () => {
      mockAlpacaInstance.getAccount.mockRejectedValue(new Error('Unauthorized'));

      const account = await service.getAccountInfo();

      expect(account).toBeNull();
    });

    it('should handle missing optional fields', async () => {
      mockAlpacaInstance.getAccount.mockResolvedValue({
        id: 'acc123',
        account_number: '123456',
        status: 'ACTIVE',
        currency: 'USD',
        buying_power: '10000',
        cash: '5000',
        portfolio_value: '15000',
        pattern_day_trader: false,
        trading_blocked: false,
        transfers_blocked: false,
        account_blocked: false,
        created_at: '2020-01-01',
        trade_suspended_by_user: false,
        // Missing optional fields like equity, multiplier, etc.
      });

      const account = await service.getAccountInfo();

      expect(account).not.toBeNull();
      expect(account?.regt_buying_power).toBe('');
      expect(account?.multiplier).toBe('');
      expect(account?.equity).toBe('');
    });
  });
});
