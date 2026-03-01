import { CTraderApiService } from '../../external/ctrader-api-service';
import type { ExchangeCredentials } from '../../types';
import EventEmitter from 'events';

// Mock fetch for token refresh
const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

// Response handlers keyed by payloadType
let wsResponseHandlers: Record<number, (msg: { clientMsgId: string; payloadType: number; payload: Record<string, unknown> }) => void> = {};

// Default response handler
function defaultHandler(instance: MockWebSocket, msg: { clientMsgId: string; payloadType: number; payload: Record<string, unknown> }) {
  switch (msg.payloadType) {
    case 2100: // APP_AUTH_REQ
      instance.respondTo(msg.clientMsgId, 2101, {});
      break;
    case 2102: // ACCOUNT_AUTH_REQ
      instance.respondTo(msg.clientMsgId, 2103, {});
      break;
    case 2149: // GET_ACCOUNTS_BY_ACCESS_TOKEN_REQ
      instance.respondTo(msg.clientMsgId, 2150, {
        ctidTraderAccount: [
          { ctidTraderAccountId: 12345, isLive: true, brokerName: 'TestBroker', balance: 1000000 },
        ],
      });
      break;
    case 2121: // TRADER_REQ
      instance.respondTo(msg.clientMsgId, 2122, {
        trader: {
          ctidTraderAccountId: 12345,
          balance: 1000000,
          moneyDigits: 2,
          leverageInCents: 10000,
          brokerName: 'TestBroker',
          traderLogin: 99999,
        },
      });
      break;
    case 2124: // RECONCILE_REQ
      instance.respondTo(msg.clientMsgId, 2125, { position: [] });
      break;
    case 2133: // DEAL_LIST_REQ
      instance.respondTo(msg.clientMsgId, 2134, { deal: [] });
      break;
    case 51: // HEARTBEAT - no response needed
      break;
  }
}

class MockWebSocket extends EventEmitter {
  static OPEN = 1;
  readyState = MockWebSocket.OPEN;

  constructor() {
    super();
    // Auto-open on next tick
    setTimeout(() => this.emit('open'), 0);
  }

  send(raw: string) {
    const msg = JSON.parse(raw);
    // Check for custom handler first, then default
    if (wsResponseHandlers[msg.payloadType]) {
      wsResponseHandlers[msg.payloadType]!(msg);
    } else {
      defaultHandler(this, msg);
    }
  }

  close() {
    this.readyState = 3;
    this.emit('close');
  }

  respondTo(clientMsgId: string, payloadType: number, payload: Record<string, unknown>) {
    const data = JSON.stringify({ clientMsgId, payloadType, payload });
    this.emit('message', Buffer.from(data));
  }

  respondError(clientMsgId: string, errorCode: string, description: string) {
    const data = JSON.stringify({
      clientMsgId,
      payloadType: 2142, // PROTO_OA_ERROR_RES
      payload: { errorCode, description },
    });
    this.emit('message', Buffer.from(data));
  }
}

// Track all created instances so handlers can reference the current one
let latestWsInstance: MockWebSocket;

jest.mock('ws', () => {
  return jest.fn().mockImplementation(() => {
    latestWsInstance = new MockWebSocket();
    return latestWsInstance;
  });
});

describe('CTraderApiService', () => {
  const mockCredentials: ExchangeCredentials = {
    userUid: 'user_test123',
    exchange: 'ctrader',
    label: 'cTrader Account',
    apiKey: 'test_access_token',
    apiSecret: 'test_refresh_token',
  };

  const mockCredentialsNoRefresh: ExchangeCredentials = {
    userUid: 'user_test123',
    exchange: 'ctrader',
    label: 'cTrader Account',
    apiKey: 'test_access_token',
    apiSecret: '',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    wsResponseHandlers = {};
    process.env.CTRADER_CLIENT_ID = 'test_client_id';
    process.env.CTRADER_CLIENT_SECRET = 'test_client_secret';
  });

  afterEach(() => {
    delete process.env.CTRADER_CLIENT_ID;
    delete process.env.CTRADER_CLIENT_SECRET;
  });

  describe('constructor', () => {
    it('should throw error when apiKey is missing', () => {
      expect(() => new CTraderApiService({
        ...mockCredentials,
        apiKey: '',
      })).toThrow('cTrader requires apiKey (access_token from OAuth)');
    });

    it('should create service with valid credentials', () => {
      const service = new CTraderApiService(mockCredentials);
      expect(service).toBeDefined();
    });

    it('should default to live mode', () => {
      const service = new CTraderApiService(mockCredentials);
      expect(service.getIsLive()).toBe(true);
    });

    it('should set demo mode when passphrase is demo', () => {
      const service = new CTraderApiService({ ...mockCredentials, passphrase: 'demo' });
      expect(service.getIsLive()).toBe(false);
    });
  });

  describe('getAccounts', () => {
    it('should return accounts from cTrader', async () => {
      const service = new CTraderApiService(mockCredentials);
      const accounts = await service.getAccounts();

      expect(accounts).toHaveLength(1);
      expect(accounts[0]?.ctidTraderAccountId).toBe(12345);
      expect(accounts[0]?.isLive).toBe(true);
    });

    it('should return empty array when no accounts', async () => {
      wsResponseHandlers[2149] = (msg) => {
        latestWsInstance.respondTo(msg.clientMsgId, 2150, {});
      };

      const service = new CTraderApiService(mockCredentials);
      const accounts = await service.getAccounts();

      expect(accounts).toEqual([]);
    });
  });

  describe('token refresh on CH_ACCESS_TOKEN_INVALID', () => {
    it('should auto-refresh token in getAccounts and retry', async () => {
      let callCount = 0;

      wsResponseHandlers[2149] = (msg) => {
        callCount++;
        if (callCount === 1) {
          latestWsInstance.respondError(msg.clientMsgId, 'CH_ACCESS_TOKEN_INVALID', 'Access token expired');
        } else {
          latestWsInstance.respondTo(msg.clientMsgId, 2150, {
            ctidTraderAccount: [
              { ctidTraderAccountId: 12345, isLive: true, brokerName: 'TestBroker' },
            ],
          });
        }
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'new_access_token', expires_in: 3600 }),
      });

      const service = new CTraderApiService(mockCredentials);
      const accounts = await service.getAccounts();

      expect(accounts).toHaveLength(1);
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://openapi.ctrader.com/apps/token',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    it('should auto-refresh token in authenticateAccount and retry', async () => {
      let accountAuthCount = 0;

      wsResponseHandlers[2102] = (msg) => {
        accountAuthCount++;
        if (accountAuthCount === 1) {
          latestWsInstance.respondError(msg.clientMsgId, 'CH_ACCESS_TOKEN_INVALID', 'Access token expired');
        } else {
          latestWsInstance.respondTo(msg.clientMsgId, 2103, {});
        }
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'new_access_token', expires_in: 3600 }),
      });

      const service = new CTraderApiService(mockCredentials);
      service.setActiveAccount(12345);

      const trader = await service.getTraderInfo(12345);

      expect(trader).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should throw when no refresh token available', async () => {
      wsResponseHandlers[2149] = (msg) => {
        latestWsInstance.respondError(msg.clientMsgId, 'CH_ACCESS_TOKEN_INVALID', 'Access token expired');
      };

      const service = new CTraderApiService(mockCredentialsNoRefresh);

      await expect(service.getAccounts()).rejects.toThrow(
        'cTrader access token expired and no refresh token is stored'
      );
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should throw when token refresh fails', async () => {
      wsResponseHandlers[2149] = (msg) => {
        latestWsInstance.respondError(msg.clientMsgId, 'CH_ACCESS_TOKEN_INVALID', 'Access token expired');
      };

      mockFetch.mockResolvedValueOnce({
        ok: false,
        text: async () => 'Invalid refresh token',
      });

      const service = new CTraderApiService(mockCredentials);

      await expect(service.getAccounts()).rejects.toThrow('Token refresh failed');
    });

    it('should rethrow non-token errors without attempting refresh', async () => {
      wsResponseHandlers[2149] = (msg) => {
        latestWsInstance.respondError(msg.clientMsgId, 'SOME_OTHER_ERROR', 'Something else went wrong');
      };

      const service = new CTraderApiService(mockCredentials);

      await expect(service.getAccounts()).rejects.toThrow('SOME_OTHER_ERROR');
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('refreshToken', () => {
    it('should call token endpoint with correct params', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'refreshed_token', expires_in: 7200 }),
      });

      const service = new CTraderApiService(mockCredentials);
      const result = await service.refreshToken('my_refresh_token');

      expect(result.access_token).toBe('refreshed_token');
      expect(result.expires_in).toBe(7200);

      const [url, options] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://openapi.ctrader.com/apps/token');
      expect(options.method).toBe('POST');

      const body = new URLSearchParams(options.body);
      expect(body.get('grant_type')).toBe('refresh_token');
      expect(body.get('refresh_token')).toBe('my_refresh_token');
      expect(body.get('client_id')).toBe('test_client_id');
      expect(body.get('client_secret')).toBe('test_client_secret');
    });

    it('should call token refresh handler when refresh succeeds', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'refreshed_token',
          refresh_token: 'rotated_refresh_token',
          expires_in: 7200,
        }),
      });

      const onTokenRefreshed = jest.fn();
      const service = new CTraderApiService(mockCredentials, { onTokenRefreshed });
      await service.refreshToken('my_refresh_token');

      expect(onTokenRefreshed).toHaveBeenCalledWith({
        accessToken: 'refreshed_token',
        refreshToken: 'rotated_refresh_token',
        expiresIn: 7200,
      });
    });

    it('should throw on refresh failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        text: async () => 'Bad Request',
      });

      const service = new CTraderApiService(mockCredentials);

      await expect(service.refreshToken('bad_token')).rejects.toThrow('Token refresh failed: Bad Request');
    });
  });

  describe('testConnection', () => {
    it('should return true when accounts exist', async () => {
      const service = new CTraderApiService(mockCredentials);
      const result = await service.testConnection();
      expect(result).toBe(true);
    });

    it('should return false when no accounts', async () => {
      wsResponseHandlers[2149] = (msg) => {
        latestWsInstance.respondTo(msg.clientMsgId, 2150, {});
      };

      const service = new CTraderApiService(mockCredentials);
      const result = await service.testConnection();
      expect(result).toBe(false);
    });
  });

  describe('getAccountBalance', () => {
    it('should return balance data', async () => {
      const service = new CTraderApiService(mockCredentials);
      service.setActiveAccount(12345);

      const balance = await service.getAccountBalance(12345);

      expect(balance.balance).toBe(10000); // 1000000 / 10^2
      expect(balance.currency).toBe('USD');
    });
  });

  describe('getDeals', () => {
    it('should return deals list', async () => {
      const mockDeals = [
        {
          dealId: 1001,
          orderId: 2001,
          positionId: 3001,
          volume: 10000,
          filledVolume: 10000,
          symbolId: 1,
          createTimestamp: Date.now(),
          executionTimestamp: Date.now(),
          utcLastUpdateTimestamp: Date.now(),
          executionPrice: 15000000,
          tradeSide: 'BUY',
          dealStatus: 'FILLED',
          commission: 150,
        },
      ];

      wsResponseHandlers[2133] = (msg) => {
        latestWsInstance.respondTo(msg.clientMsgId, 2134, { deal: mockDeals });
      };

      const service = new CTraderApiService(mockCredentials);
      service.setActiveAccount(12345);

      const deals = await service.getDeals(12345, Date.now() - 86400000, Date.now());

      expect(deals).toHaveLength(1);
      expect(deals[0]?.dealId).toBe(1001);
      expect(deals[0]?.dealStatus).toBe('FILLED');
    });

    it('should return empty array when no deals', async () => {
      wsResponseHandlers[2133] = (msg) => {
        latestWsInstance.respondTo(msg.clientMsgId, 2134, {});
      };

      const service = new CTraderApiService(mockCredentials);
      service.setActiveAccount(12345);

      const deals = await service.getDeals(12345, Date.now() - 86400000, Date.now());
      expect(deals).toEqual([]);
    });
  });
});
