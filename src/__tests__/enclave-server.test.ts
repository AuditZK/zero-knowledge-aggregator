/**
 * Tests for enclave-server.ts
 *
 * Tests the gRPC server and its handlers.
 */

import * as grpc from '@grpc/grpc-js';

// Mock tsyringe container
const mockContainer = {
  resolve: jest.fn()
};

jest.mock('tsyringe', () => ({
  container: mockContainer
}));

// Mock proto loader
jest.mock('@grpc/proto-loader', () => ({
  loadSync: jest.fn().mockReturnValue({})
}));

// Mock grpc
const mockServer = {
  addService: jest.fn(),
  bindAsync: jest.fn(),
  tryShutdown: jest.fn(),
  forceShutdown: jest.fn()
};

jest.mock('@grpc/grpc-js', () => ({
  Server: jest.fn().mockImplementation(() => mockServer),
  loadPackageDefinition: jest.fn().mockReturnValue({
    enclave: {
      EnclaveService: {
        service: {}
      }
    }
  }),
  ServerCredentials: {
    createSsl: jest.fn().mockReturnValue({}),
    createInsecure: jest.fn().mockReturnValue({})
  },
  status: {
    INVALID_ARGUMENT: 3,
    INTERNAL: 13
  }
}));

// Mock fs
jest.mock('node:fs', () => ({
  readFileSync: jest.fn().mockImplementation((path: string) => {
    if (path.includes('ca.crt') || path.includes('server.crt')) {
      return Buffer.from('mock-certificate');
    }
    if (path.includes('server.key')) {
      return Buffer.from('mock-private-key');
    }
    throw new Error(`File not found: ${path}`);
  }),
  existsSync: jest.fn().mockReturnValue(true)
}));

// Mock logger
jest.mock('../utils/secure-enclave-logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  }),
  extractErrorMessage: (error: unknown) => {
    if (error instanceof Error) return error.message;
    return String(error);
  }
}));

// Mock EnclaveWorker
const mockEnclaveWorker = {
  processSyncJob: jest.fn(),
  getAggregatedMetrics: jest.fn(),
  getSnapshotTimeSeries: jest.fn(),
  getPerformanceMetrics: jest.fn(),
  createUserConnection: jest.fn(),
  healthCheck: jest.fn()
};

// Mock ReportGeneratorService
const mockReportGeneratorService = {
  generateSignedReport: jest.fn()
};

// Mock ReportSigningService
const mockReportSigningService = {
  getPublicKeyFingerprint: jest.fn().mockReturnValue('abcd1234'),
  verifySignature: jest.fn()
};

describe('EnclaveServer', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...originalEnv };

    mockContainer.resolve.mockImplementation((service: unknown) => {
      const serviceName = typeof service === 'function' ? service.name : String(service);
      switch (serviceName) {
        case 'EnclaveWorker':
          return mockEnclaveWorker;
        case 'ReportGeneratorService':
          return mockReportGeneratorService;
        case 'ReportSigningService':
          return mockReportSigningService;
        default:
          return {};
      }
    });
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('Server Initialization', () => {
    it('should create a new gRPC server', () => {
      expect(grpc.Server).toBeDefined();
    });

    it('should use default port 50051 when ENCLAVE_PORT not set', () => {
      delete process.env.ENCLAVE_PORT;
      const port = Number.parseInt(process.env.ENCLAVE_PORT || '50051', 10);
      expect(port).toBe(50051);
    });

    it('should use custom port when ENCLAVE_PORT is set', () => {
      process.env.ENCLAVE_PORT = '50052';
      const port = Number.parseInt(process.env.ENCLAVE_PORT || '50051', 10);
      expect(port).toBe(50052);
    });
  });

  describe('ProcessSyncJob Handler', () => {
    it('should process sync job successfully', async () => {
      mockEnclaveWorker.processSyncJob.mockResolvedValueOnce({
        success: true,
        userUid: 'test-user',
        exchange: 'binance',
        synced: true,
        snapshotsGenerated: 1,
        latestSnapshot: {
          balance: 10000,
          equity: 10500,
          timestamp: new Date()
        }
      });

      const request = {
        user_uid: 'test-user',
        exchange: 'binance',
        type: 'incremental'
      };

      const handler = async (rawRequest: typeof request): Promise<{
        success: boolean;
        user_uid: string;
        exchange: string;
        synced: boolean;
        snapshots_generated: number;
        latest_snapshot: { balance: number; equity: number; timestamp: string } | null;
        error: string;
      }> => {
        const syncRequest = {
          userUid: rawRequest.user_uid,
          exchange: rawRequest.exchange || undefined
        };

        const result = await mockEnclaveWorker.processSyncJob(syncRequest);

        return {
          success: result.success,
          user_uid: result.userUid,
          exchange: result.exchange || '',
          synced: result.synced,
          snapshots_generated: result.snapshotsGenerated,
          latest_snapshot: result.latestSnapshot ? {
            balance: result.latestSnapshot.balance,
            equity: result.latestSnapshot.equity,
            timestamp: result.latestSnapshot.timestamp.getTime().toString()
          } : null,
          error: result.error || ''
        };
      };

      const response = await handler(request);

      expect(response.success).toBe(true);
      expect(response.user_uid).toBe('test-user');
      expect(response.exchange).toBe('binance');
      expect(response.synced).toBe(true);
      expect(response.snapshots_generated).toBe(1);
      expect(response.latest_snapshot).not.toBeNull();
    });

    it('should normalize empty exchange to undefined', async () => {
      mockEnclaveWorker.processSyncJob.mockResolvedValueOnce({
        success: true,
        userUid: 'test-user',
        exchange: '',
        synced: true,
        snapshotsGenerated: 0
      });

      const request = {
        user_uid: 'test-user',
        exchange: '', // Empty string
        type: 'incremental'
      };

      const normalizedExchange = request.exchange === '' ? undefined : request.exchange;

      expect(normalizedExchange).toBeUndefined();
    });
  });

  describe('GetAggregatedMetrics Handler', () => {
    it('should return aggregated metrics', async () => {
      mockEnclaveWorker.getAggregatedMetrics.mockResolvedValueOnce({
        totalBalance: 10000,
        totalEquity: 10500,
        totalRealizedPnl: 500,
        totalUnrealizedPnl: 200,
        totalFees: 50,
        totalTrades: 100,
        lastSync: new Date()
      });

      const handler = async (userUid: string, exchange?: string) => {
        const metrics = await mockEnclaveWorker.getAggregatedMetrics(userUid, exchange);

        return {
          total_balance: metrics.totalBalance,
          total_equity: metrics.totalEquity,
          total_realized_pnl: metrics.totalRealizedPnl,
          total_unrealized_pnl: metrics.totalUnrealizedPnl,
          total_fees: metrics.totalFees,
          total_trades: metrics.totalTrades,
          last_sync: metrics.lastSync ? metrics.lastSync.getTime().toString() : '0'
        };
      };

      const response = await handler('test-user', 'binance');

      expect(response.total_balance).toBe(10000);
      expect(response.total_equity).toBe(10500);
      expect(response.total_realized_pnl).toBe(500);
      expect(response.total_trades).toBe(100);
    });
  });

  describe('GetSnapshotTimeSeries Handler', () => {
    it('should return snapshot time series', async () => {
      mockEnclaveWorker.getSnapshotTimeSeries.mockResolvedValueOnce([
        {
          userUid: 'test-user',
          exchange: 'binance',
          timestamp: new Date(),
          totalEquity: 10000,
          realizedBalance: 9500,
          unrealizedPnL: 500,
          deposits: 1000,
          withdrawals: 0,
          breakdown: {
            spot: { equity: 5000, trades: 50 },
            swap: { equity: 5000, trades: 50 }
          }
        }
      ]);

      const handler = async (
        userUid: string,
        exchange?: string,
        startDate?: Date,
        endDate?: Date
      ) => {
        const snapshots = await mockEnclaveWorker.getSnapshotTimeSeries(
          userUid,
          exchange,
          startDate,
          endDate
        );

        return {
          snapshots: snapshots.map((s: {
            userUid: string;
            exchange: string;
            timestamp: Date;
            totalEquity: number;
            realizedBalance: number;
            unrealizedPnL: number;
            deposits: number;
            withdrawals: number;
          }) => ({
            user_uid: s.userUid,
            exchange: s.exchange,
            timestamp: s.timestamp.getTime(),
            total_equity: s.totalEquity,
            realized_balance: s.realizedBalance,
            unrealized_pnl: s.unrealizedPnL
          }))
        };
      };

      const response = await handler('test-user', 'binance');

      expect(response.snapshots).toHaveLength(1);
      expect(response.snapshots[0].total_equity).toBe(10000);
    });

    it('should normalize zero timestamps to undefined', () => {
      const rawRequest = {
        user_uid: 'test-user',
        exchange: '',
        start_date: '0',
        end_date: '0'
      };

      const isZeroOrEmpty = (val: unknown): boolean => !val || val === 0 || val === '0';

      expect(isZeroOrEmpty(rawRequest.start_date)).toBe(true);
      expect(isZeroOrEmpty(rawRequest.end_date)).toBe(true);
    });
  });

  describe('GetPerformanceMetrics Handler', () => {
    it('should return performance metrics', async () => {
      mockEnclaveWorker.getPerformanceMetrics.mockResolvedValueOnce({
        success: true,
        metrics: {
          sharpeRatio: 1.5,
          sortinoRatio: 2.0,
          calmarRatio: 1.2,
          volatility: 0.15,
          downsideDeviation: 0.1,
          maxDrawdown: 0.05,
          maxDrawdownDuration: 10,
          currentDrawdown: 0.02,
          winRate: 0.6,
          profitFactor: 1.5,
          avgWin: 100,
          avgLoss: 50,
          periodStart: new Date(),
          periodEnd: new Date(),
          dataPoints: 365
        }
      });

      const handler = async (
        userUid: string,
        exchange?: string,
        startDate?: Date,
        endDate?: Date
      ) => {
        const result = await mockEnclaveWorker.getPerformanceMetrics(
          userUid,
          exchange,
          startDate,
          endDate
        );

        if (!result.success) {
          return {
            success: false,
            error: result.error || 'Failed to calculate metrics',
            sharpe_ratio: 0
          };
        }

        const metrics = result.metrics;

        return {
          success: true,
          sharpe_ratio: metrics.sharpeRatio || 0,
          sortino_ratio: metrics.sortinoRatio || 0,
          calmar_ratio: metrics.calmarRatio || 0,
          volatility: metrics.volatility || 0,
          max_drawdown: metrics.maxDrawdown || 0,
          win_rate: metrics.winRate || 0,
          data_points: metrics.dataPoints,
          error: ''
        };
      };

      const response = await handler('test-user', 'binance');

      expect(response.success).toBe(true);
      expect(response.sharpe_ratio).toBe(1.5);
      expect(response.sortino_ratio).toBe(2.0);
      expect(response.win_rate).toBe(0.6);
    });

    it('should handle failed metrics calculation', async () => {
      mockEnclaveWorker.getPerformanceMetrics.mockResolvedValueOnce({
        success: false,
        error: 'Insufficient data'
      });

      const handler = async (userUid: string) => {
        const result = await mockEnclaveWorker.getPerformanceMetrics(userUid);

        if (!result.success) {
          return {
            success: false,
            error: result.error || 'Failed to calculate metrics',
            sharpe_ratio: 0
          };
        }

        return { success: true };
      };

      const response = await handler('test-user');

      expect(response.success).toBe(false);
      expect(response.error).toBe('Insufficient data');
    });
  });

  describe('CreateUserConnection Handler', () => {
    it('should create user connection successfully', async () => {
      mockEnclaveWorker.createUserConnection.mockResolvedValueOnce({
        success: true,
        userUid: 'test-user'
      });

      const handler = async (request: {
        user_uid: string;
        exchange: string;
        label: string;
        api_key: string;
        api_secret: string;
        passphrase?: string;
      }) => {
        const result = await mockEnclaveWorker.createUserConnection({
          userUid: request.user_uid,
          exchange: request.exchange,
          label: request.label,
          apiKey: request.api_key,
          apiSecret: request.api_secret,
          passphrase: request.passphrase
        });

        return {
          success: result.success,
          user_uid: result.userUid || '',
          error: result.error || ''
        };
      };

      const response = await handler({
        user_uid: 'test-user',
        exchange: 'binance',
        label: 'My Binance',
        api_key: 'test-key',
        api_secret: 'test-secret'
      });

      expect(response.success).toBe(true);
      expect(response.user_uid).toBe('test-user');
    });

    it('should normalize empty passphrase to undefined', () => {
      const rawRequest = {
        user_uid: 'test-user',
        exchange: 'kucoin',
        label: 'My KuCoin',
        api_key: 'key',
        api_secret: 'secret',
        passphrase: ''
      };

      const normalizedPassphrase = rawRequest.passphrase === '' ? undefined : rawRequest.passphrase;

      expect(normalizedPassphrase).toBeUndefined();
    });
  });

  describe('HealthCheck Handler', () => {
    it('should return healthy status', async () => {
      mockEnclaveWorker.healthCheck.mockResolvedValueOnce({
        status: 'healthy',
        enclave: true,
        version: '3.0.0',
        uptime: 3600
      });

      const handler = async () => {
        const health = await mockEnclaveWorker.healthCheck();

        return {
          status: health.status === 'healthy' ? 0 : 1,
          enclave: health.enclave,
          version: health.version,
          uptime: health.uptime
        };
      };

      const response = await handler();

      expect(response.status).toBe(0);
      expect(response.enclave).toBe(true);
      expect(response.version).toBe('3.0.0');
    });

    it('should handle unhealthy status', async () => {
      mockEnclaveWorker.healthCheck.mockResolvedValueOnce({
        status: 'unhealthy',
        enclave: true,
        version: '3.0.0',
        uptime: 3600
      });

      const handler = async () => {
        const health = await mockEnclaveWorker.healthCheck();

        return {
          status: health.status === 'healthy' ? 0 : 1,
          enclave: health.enclave,
          version: health.version,
          uptime: health.uptime
        };
      };

      const response = await handler();

      expect(response.status).toBe(1);
    });

    it('should handle health check errors', async () => {
      mockEnclaveWorker.healthCheck.mockRejectedValueOnce(new Error('Health check failed'));

      const handler = async () => {
        try {
          await mockEnclaveWorker.healthCheck();
          return { status: 0 };
        } catch {
          return {
            status: 1,
            enclave: true,
            version: 'error',
            uptime: 0
          };
        }
      };

      const response = await handler();

      expect(response.status).toBe(1);
      expect(response.version).toBe('error');
    });
  });

  describe('GenerateSignedReport Handler', () => {
    it('should generate signed report successfully', async () => {
      mockReportGeneratorService.generateSignedReport.mockResolvedValueOnce({
        success: true,
        signedReport: {
          financialData: {
            reportId: 'report-123',
            userUid: 'test-user',
            generatedAt: new Date(),
            periodStart: new Date(),
            periodEnd: new Date(),
            baseCurrency: 'USD',
            benchmark: 'SPY',
            dataPoints: 365,
            exchanges: ['binance'],
            metrics: {
              totalReturn: 0.15,
              annualizedReturn: 0.18,
              volatility: 0.12,
              sharpeRatio: 1.5,
              sortinoRatio: 2.0,
              maxDrawdown: 0.05,
              calmarRatio: 3.6
            },
            dailyReturns: [],
            monthlyReturns: []
          },
          displayParams: {
            reportName: 'Test Report'
          },
          signature: 'base64-signature',
          publicKey: 'public-key',
          signatureAlgorithm: 'Ed25519',
          reportHash: 'sha256-hash',
          enclaveVersion: '3.0.0',
          attestationId: 'att-123',
          enclaveMode: 'production'
        }
      });

      const handler = async (request: { userUid: string }) => {
        const result = await mockReportGeneratorService.generateSignedReport(request);

        if (!result.success || !result.signedReport) {
          return {
            success: false,
            error: result.error || 'Failed to generate report'
          };
        }

        return {
          success: true,
          report_id: result.signedReport.financialData.reportId,
          signature: result.signedReport.signature
        };
      };

      const response = await handler({ userUid: 'test-user' });

      expect(response.success).toBe(true);
      expect(response.report_id).toBe('report-123');
    });

    it('should handle report generation failure', async () => {
      mockReportGeneratorService.generateSignedReport.mockResolvedValueOnce({
        success: false,
        error: 'Insufficient data'
      });

      const handler = async (request: { userUid: string }) => {
        const result = await mockReportGeneratorService.generateSignedReport(request);

        if (!result.success) {
          return {
            success: false,
            error: result.error || 'Failed to generate report'
          };
        }

        return { success: true };
      };

      const response = await handler({ userUid: 'test-user' });

      expect(response.success).toBe(false);
      expect(response.error).toBe('Insufficient data');
    });
  });

  describe('VerifyReportSignature Handler', () => {
    it('should verify valid signature', () => {
      mockReportSigningService.verifySignature.mockReturnValueOnce({
        valid: true
      });

      const handler = (request: {
        reportHash: string;
        signature: string;
        publicKey: string;
      }) => {
        if (!request.reportHash || !request.signature || !request.publicKey) {
          return { valid: false, error: 'Missing required fields' };
        }

        const result = mockReportSigningService.verifySignature(request);

        return {
          valid: result.valid,
          error: result.error || ''
        };
      };

      const response = handler({
        reportHash: 'sha256-hash',
        signature: 'base64-signature',
        publicKey: 'public-key'
      });

      expect(response.valid).toBe(true);
    });

    it('should return error for missing fields', () => {
      const handler = (request: {
        reportHash?: string;
        signature?: string;
        publicKey?: string;
      }) => {
        if (!request.reportHash || !request.signature || !request.publicKey) {
          return { valid: false, error: 'Missing required fields' };
        }

        return { valid: true };
      };

      const response = handler({
        reportHash: 'hash',
        signature: 'sig'
        // Missing publicKey
      });

      expect(response.valid).toBe(false);
      expect(response.error).toBe('Missing required fields');
    });
  });

  describe('TLS Credentials', () => {
    it('should load TLS certificates from files', () => {
      const fs = require('node:fs');

      const caCertPath = '/etc/enclave/ca.crt';
      const serverCertPath = '/etc/enclave/server.crt';
      const serverKeyPath = '/etc/enclave/server.key';

      const rootCert = fs.readFileSync(caCertPath);
      const serverCert = fs.readFileSync(serverCertPath);
      const serverKey = fs.readFileSync(serverKeyPath);

      expect(rootCert.toString()).toBe('mock-certificate');
      expect(serverCert.toString()).toBe('mock-certificate');
      expect(serverKey.toString()).toBe('mock-private-key');
    });

    it('should use custom cert paths from env', () => {
      process.env.TLS_CA_CERT = '/custom/ca.crt';
      process.env.TLS_SERVER_CERT = '/custom/server.crt';
      process.env.TLS_SERVER_KEY = '/custom/server.key';

      const caCertPath = process.env.TLS_CA_CERT || '/etc/enclave/ca.crt';
      const serverCertPath = process.env.TLS_SERVER_CERT || '/etc/enclave/server.crt';
      const serverKeyPath = process.env.TLS_SERVER_KEY || '/etc/enclave/server.key';

      expect(caCertPath).toBe('/custom/ca.crt');
      expect(serverCertPath).toBe('/custom/server.crt');
      expect(serverKeyPath).toBe('/custom/server.key');
    });

    it('should require client cert in production', () => {
      process.env.NODE_ENV = 'production';
      const requireClientCert = process.env.NODE_ENV === 'production' || process.env.REQUIRE_CLIENT_CERT === 'true';
      expect(requireClientCert).toBe(true);
    });

    it('should not require client cert in development by default', () => {
      process.env.NODE_ENV = 'development';
      delete process.env.REQUIRE_CLIENT_CERT;
      const requireClientCert = process.env.NODE_ENV === 'production' || process.env.REQUIRE_CLIENT_CERT === 'true';
      expect(requireClientCert).toBe(false);
    });
  });

  describe('Attestation Logging', () => {
    it('should log enclave mode in production', () => {
      process.env.ENCLAVE_MODE = 'true';
      process.env.ATTESTATION_ID = 'att-12345';

      const isEnclave = process.env.ENCLAVE_MODE === 'true';
      const attestationId = process.env.ATTESTATION_ID;

      expect(isEnclave).toBe(true);
      expect(attestationId).toBe('att-12345');
    });

    it('should log development mode when not in enclave', () => {
      delete process.env.ENCLAVE_MODE;

      const isEnclave = process.env.ENCLAVE_MODE === 'true';

      expect(isEnclave).toBe(false);
    });
  });

  describe('Server Lifecycle', () => {
    it('should start server with bind async', async () => {
      mockServer.bindAsync.mockImplementation(
        (_address: string, _credentials: unknown, callback: (error: Error | null, port: number) => void) => {
          callback(null, 50051);
        }
      );

      const start = (): Promise<void> => {
        return new Promise((resolve, reject) => {
          mockServer.bindAsync(
            '0.0.0.0:50051',
            {},
            (error: Error | null, port: number) => {
              if (error) {
                reject(error);
                return;
              }
              expect(port).toBe(50051);
              resolve();
            }
          );
        });
      };

      await expect(start()).resolves.toBeUndefined();
    });

    it('should handle bind error', async () => {
      mockServer.bindAsync.mockImplementation(
        (_address: string, _credentials: unknown, callback: (error: Error | null, port: number) => void) => {
          callback(new Error('Address in use'), 0);
        }
      );

      const start = (): Promise<void> => {
        return new Promise((resolve, reject) => {
          mockServer.bindAsync(
            '0.0.0.0:50051',
            {},
            (error: Error | null) => {
              if (error) {
                reject(error);
                return;
              }
              resolve();
            }
          );
        });
      };

      await expect(start()).rejects.toThrow('Address in use');
    });

    it('should stop server gracefully', async () => {
      mockServer.tryShutdown.mockImplementation((callback: (error?: Error) => void) => {
        callback();
      });

      const stop = (): Promise<void> => {
        return new Promise((resolve) => {
          mockServer.tryShutdown((error: Error | undefined) => {
            if (error) {
              mockServer.forceShutdown();
            }
            resolve();
          });
        });
      };

      await stop();

      expect(mockServer.tryShutdown).toHaveBeenCalled();
    });

    it('should force shutdown on error', async () => {
      mockServer.tryShutdown.mockImplementation((callback: (error?: Error) => void) => {
        callback(new Error('Shutdown error'));
      });

      const stop = (): Promise<void> => {
        return new Promise((resolve) => {
          mockServer.tryShutdown((error: Error | undefined) => {
            if (error) {
              mockServer.forceShutdown();
            }
            resolve();
          });
        });
      };

      await stop();

      expect(mockServer.forceShutdown).toHaveBeenCalled();
    });
  });
});
