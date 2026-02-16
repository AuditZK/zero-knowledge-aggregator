import { ReportGeneratorService } from '../../services/report-generator.service';
import { SnapshotDataRepository } from '../../core/repositories/snapshot-data-repository';
import { SignedReportRepository } from '../../core/repositories/signed-report-repository';
import { ExchangeConnectionRepository } from '../../core/repositories/exchange-connection-repository';
import { ReportSigningService } from '../../services/report-signing.service';
import type { ReportRequest, SignedReport, SignedFinancialData, DisplayParameters } from '../../types/report.types';

// Mock the logger
jest.mock('../../utils/secure-enclave-logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

describe('ReportGeneratorService', () => {
  let service: ReportGeneratorService;
  let mockSnapshotRepo: jest.Mocked<SnapshotDataRepository>;
  let mockReportRepo: jest.Mocked<SignedReportRepository>;
  let mockSigningService: jest.Mocked<ReportSigningService>;
  let mockConnectionRepo: jest.Mocked<ExchangeConnectionRepository>;

  // Sample snapshot data for testing
  const createMockSnapshots = (days: number, startEquity: number = 100000) => {
    const snapshots = [];
    let equity = startEquity;
    const baseDate = new Date('2024-01-01');

    for (let i = 0; i < days; i++) {
      const date = new Date(baseDate);
      date.setDate(date.getDate() + i);

      // Simulate some daily returns between -2% and +2%
      const dailyReturn = (Math.random() - 0.5) * 0.04;
      equity = equity * (1 + dailyReturn);
      const unrealizedPnL = equity * 0.02;

      snapshots.push({
        id: `snapshot_${i}`,
        userUid: 'user_test123',
        timestamp: date.toISOString(),
        totalEquity: equity,
        realizedBalance: equity * 0.8,
        unrealizedPnL,
        deposits: i === 0 ? startEquity : 0,
        withdrawals: 0,
        exchange: 'binance',
        label: '',
        createdAt: date,
        updatedAt: date,
      });
    }
    return snapshots;
  };

  const createMockSignedReport = (financialData: SignedFinancialData, displayParams: DisplayParameters): SignedReport => ({
    financialData,
    displayParams,
    signature: 'mock-signature-base64',
    publicKey: 'mock-public-key-base64',
    signatureAlgorithm: 'ECDSA-P256-SHA256',
    enclaveVersion: '3.0.0',
    enclaveMode: 'development',
    reportHash: 'mock-hash-256',
  });

  beforeEach(() => {
    // Create mocks
    mockSnapshotRepo = {
      getSnapshotData: jest.fn(),
    } as unknown as jest.Mocked<SnapshotDataRepository>;

    mockReportRepo = {
      findByPeriod: jest.fn(),
      save: jest.fn(),
    } as unknown as jest.Mocked<SignedReportRepository>;

    mockSigningService = {
      signFinancialData: jest.fn(),
      getPublicKey: jest.fn().mockReturnValue('mock-public-key'),
    } as unknown as jest.Mocked<ReportSigningService>;

    mockConnectionRepo = {
      getKycLevelsForUser: jest.fn().mockResolvedValue(new Map()),
      getPaperStatusForUser: jest.fn().mockResolvedValue(new Map()),
    } as unknown as jest.Mocked<ExchangeConnectionRepository>;

    // Default mock implementations
    mockReportRepo.findByPeriod.mockResolvedValue(null);
    mockReportRepo.save.mockResolvedValue(undefined as never);

    service = new ReportGeneratorService(
      mockSnapshotRepo,
      mockReportRepo,
      mockConnectionRepo,
      mockSigningService
    );
  });

  describe('generateSignedReport', () => {
    describe('successful report generation', () => {
      it('should generate report with valid snapshot data', async () => {
        const snapshots = createMockSnapshots(30);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        mockSigningService.signFinancialData.mockImplementation((data, params) =>
          createMockSignedReport(data, params)
        );

        const request: ReportRequest = {
          userUid: 'user_test123',
          startDate: '2024-01-01',
          endDate: '2024-01-30',
        };

        const result = await service.generateSignedReport(request);

        expect(result.success).toBe(true);
        expect(result.signedReport).toBeDefined();
        expect(result.error).toBeUndefined();
        expect(mockSnapshotRepo.getSnapshotData).toHaveBeenCalledWith(
          'user_test123',
          expect.any(Date),
          expect.any(Date)
        );
      });

      it('should include core metrics in the report', async () => {
        const snapshots = createMockSnapshots(60);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        await service.generateSignedReport(request);

        expect(capturedFinancialData).not.toBeNull();
        expect(capturedFinancialData!.metrics).toHaveProperty('totalReturn');
        expect(capturedFinancialData!.metrics).toHaveProperty('annualizedReturn');
        expect(capturedFinancialData!.metrics).toHaveProperty('volatility');
        expect(capturedFinancialData!.metrics).toHaveProperty('sharpeRatio');
        expect(capturedFinancialData!.metrics).toHaveProperty('sortinoRatio');
        expect(capturedFinancialData!.metrics).toHaveProperty('maxDrawdown');
        expect(capturedFinancialData!.metrics).toHaveProperty('calmarRatio');
      });

      it('should include risk metrics when requested', async () => {
        const snapshots = createMockSnapshots(30);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
          includeRiskMetrics: true,
        };

        await service.generateSignedReport(request);

        expect(capturedFinancialData!.metrics.riskMetrics).toBeDefined();
        expect(capturedFinancialData!.metrics.riskMetrics).toHaveProperty('var95');
        expect(capturedFinancialData!.metrics.riskMetrics).toHaveProperty('var99');
        expect(capturedFinancialData!.metrics.riskMetrics).toHaveProperty('expectedShortfall');
        expect(capturedFinancialData!.metrics.riskMetrics).toHaveProperty('skewness');
        expect(capturedFinancialData!.metrics.riskMetrics).toHaveProperty('kurtosis');
      });

      it('should include drawdown data when requested', async () => {
        const snapshots = createMockSnapshots(30);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
          includeDrawdown: true,
        };

        await service.generateSignedReport(request);

        expect(capturedFinancialData!.metrics.drawdownData).toBeDefined();
        expect(capturedFinancialData!.metrics.drawdownData).toHaveProperty('maxDrawdownDuration');
        expect(capturedFinancialData!.metrics.drawdownData).toHaveProperty('currentDrawdown');
        expect(capturedFinancialData!.metrics.drawdownData).toHaveProperty('drawdownPeriods');
      });

      it('should save report for deduplication', async () => {
        const snapshots = createMockSnapshots(30);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);
        mockSigningService.signFinancialData.mockImplementation((data, params) =>
          createMockSignedReport(data, params)
        );

        const request: ReportRequest = {
          userUid: 'user_test123',
          startDate: '2024-01-01',
          endDate: '2024-01-30',
        };

        await service.generateSignedReport(request);

        expect(mockReportRepo.save).toHaveBeenCalled();
      });

      it('should use default display params when not provided', async () => {
        const snapshots = createMockSnapshots(30);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedDisplayParams: DisplayParameters | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedDisplayParams = params;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        await service.generateSignedReport(request);

        expect(capturedDisplayParams).toEqual({ reportName: 'Track Record Report' });
      });

      it('should use custom display params when provided', async () => {
        const snapshots = createMockSnapshots(30);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedDisplayParams: DisplayParameters | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedDisplayParams = params;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
          displayParams: {
            reportName: 'Custom Report',
            managerName: 'John Doe',
            firmName: 'Acme Trading',
          },
        };

        await service.generateSignedReport(request);

        expect(capturedDisplayParams).toEqual({
          reportName: 'Custom Report',
          managerName: 'John Doe',
          firmName: 'Acme Trading',
        });
      });
    });

    describe('caching behavior', () => {
      it('should return cached report if same period was already generated', async () => {
        const cachedReport = createMockSignedReport(
          {
            reportId: 'cached-report-123',
            userUid: 'user_test123',
            generatedAt: new Date('2024-01-01'),
            periodStart: new Date('2024-01-01'),
            periodEnd: new Date('2024-01-30'),
            baseCurrency: 'USD',
            dataPoints: 30,
            exchanges: ['binance'],
            metrics: {
              totalReturn: 10,
              annualizedReturn: 50,
              volatility: 15,
              sharpeRatio: 1.5,
              sortinoRatio: 2.0,
              maxDrawdown: 5,
              calmarRatio: 10,
            },
            dailyReturns: [],
            monthlyReturns: [],
          },
          { reportName: 'Old Name' }
        );

        mockReportRepo.findByPeriod.mockResolvedValue({
          id: 'report_db_123',
          reportId: 'cached-report-123',
          userUid: 'user_test123',
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-01-30'),
          benchmark: null,
          reportData: cachedReport as unknown as Record<string, unknown>,
          signature: 'sig',
          reportHash: 'hash',
          enclaveVersion: '3.0.0',
          createdAt: new Date(),
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
          startDate: '2024-01-01',
          endDate: '2024-01-30',
          displayParams: { reportName: 'New Name' },
        };

        const result = await service.generateSignedReport(request);

        expect(result.success).toBe(true);
        expect(result.cached).toBe(true);
        expect(result.signedReport?.displayParams.reportName).toBe('New Name');
        expect(mockSnapshotRepo.getSnapshotData).not.toHaveBeenCalled();
      });
    });

    describe('error handling', () => {
      it('should return error when no snapshot data found', async () => {
        mockSnapshotRepo.getSnapshotData.mockResolvedValue([]);

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        const result = await service.generateSignedReport(request);

        expect(result.success).toBe(false);
        expect(result.error).toBe('No snapshot data found for the specified period');
      });

      it('should return error when insufficient data (less than 2 days)', async () => {
        const snapshots = createMockSnapshots(1);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        const result = await service.generateSignedReport(request);

        expect(result.success).toBe(false);
        expect(result.error).toBe('Insufficient data for report generation (need at least 2 days)');
      });

      it('should handle repository errors gracefully', async () => {
        mockSnapshotRepo.getSnapshotData.mockRejectedValue(new Error('Database connection failed'));

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        const result = await service.generateSignedReport(request);

        expect(result.success).toBe(false);
        expect(result.error).toBe('Database connection failed');
      });

      it('should still return valid report if save fails', async () => {
        const snapshots = createMockSnapshots(30);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);
        mockSigningService.signFinancialData.mockImplementation((data, params) =>
          createMockSignedReport(data, params)
        );
        mockReportRepo.save.mockRejectedValue(new Error('Save failed'));

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        const result = await service.generateSignedReport(request);

        expect(result.success).toBe(true);
        expect(result.signedReport).toBeDefined();
      });
    });

    describe('multi-exchange support', () => {
      const createSnapshot = (id: string, timestamp: Date, totalEquity: number, realizedBalance: number, deposits: number, withdrawals: number, exchange: string) => ({
        id, userUid: 'user_test123', timestamp: timestamp.toISOString(), totalEquity, realizedBalance, unrealizedPnL: totalEquity * 0.02, deposits, withdrawals, exchange, label: '', createdAt: timestamp, updatedAt: timestamp
      });

      it('should aggregate equity across multiple exchanges', async () => {
        const baseDate = new Date('2024-01-01');
        const snapshots = [
          // Day 1 - Two exchanges
          createSnapshot('s1', new Date(baseDate), 50000, 40000, 50000, 0, 'binance'),
          createSnapshot('s2', new Date(baseDate), 50000, 40000, 50000, 0, 'kraken'),
          // Day 2
          createSnapshot('s3', new Date(baseDate.getTime() + 86400000), 51000, 41000, 0, 0, 'binance'),
          createSnapshot('s4', new Date(baseDate.getTime() + 86400000), 51000, 41000, 0, 0, 'kraken'),
          // Day 3
          createSnapshot('s5', new Date(baseDate.getTime() + 2 * 86400000), 52000, 42000, 0, 0, 'binance'),
          createSnapshot('s6', new Date(baseDate.getTime() + 2 * 86400000), 52000, 42000, 0, 0, 'kraken'),
        ];

        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        await service.generateSignedReport(request);

        expect(capturedFinancialData).not.toBeNull();
        expect(capturedFinancialData!.exchanges).toContain('binance');
        expect(capturedFinancialData!.exchanges).toContain('kraken');
        expect(capturedFinancialData!.exchanges.length).toBe(2);
      });

      it('should handle new exchange appearing mid-period', async () => {
        const baseDate = new Date('2024-01-01');
        const snapshots = [
          // Day 1 - Only binance
          createSnapshot('s1', new Date(baseDate), 100000, 80000, 100000, 0, 'binance'),
          // Day 2 - Binance + new Kraken
          createSnapshot('s2', new Date(baseDate.getTime() + 86400000), 101000, 81000, 0, 0, 'binance'),
          createSnapshot('s3', new Date(baseDate.getTime() + 86400000), 50000, 40000, 50000, 0, 'kraken'),
          // Day 3
          createSnapshot('s4', new Date(baseDate.getTime() + 2 * 86400000), 102000, 82000, 0, 0, 'binance'),
          createSnapshot('s5', new Date(baseDate.getTime() + 2 * 86400000), 51000, 41000, 0, 0, 'kraken'),
        ];

        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);
        mockSigningService.signFinancialData.mockImplementation((data, params) =>
          createMockSignedReport(data, params)
        );

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        const result = await service.generateSignedReport(request);

        expect(result.success).toBe(true);
      });
    });

    describe('daily returns calculation', () => {
      const createSnapshot = (id: string, timestamp: Date, totalEquity: number, realizedBalance: number, deposits: number, withdrawals: number, exchange: string) => ({
        id, userUid: 'user_test123', timestamp: timestamp.toISOString(), totalEquity, realizedBalance, unrealizedPnL: totalEquity * 0.02, deposits, withdrawals, exchange, label: '', createdAt: timestamp, updatedAt: timestamp
      });

      it('should calculate correct daily returns', async () => {
        const baseDate = new Date('2024-01-01');
        const snapshots = [
          createSnapshot('s1', new Date(baseDate), 100000, 80000, 100000, 0, 'binance'),
          createSnapshot('s2', new Date(baseDate.getTime() + 86400000), 101000, 81000, 0, 0, 'binance'),
          createSnapshot('s3', new Date(baseDate.getTime() + 2 * 86400000), 102010, 82000, 0, 0, 'binance'),
        ];

        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        await service.generateSignedReport(request);

        expect(capturedFinancialData!.dailyReturns.length).toBe(3);
        // First day return should be 0 (no previous day)
        expect(capturedFinancialData!.dailyReturns[0]!.netReturn).toBe(0);
        // Second day: (101000 - 100000) / 100000 = 1%
        expect(capturedFinancialData!.dailyReturns[1]!.netReturn).toBeCloseTo(1, 2);
        // Third day: (102010 - 101000) / 101000 = 1%
        expect(capturedFinancialData!.dailyReturns[2]!.netReturn).toBeCloseTo(1, 2);
      });

      it('should adjust for deposits in return calculation', async () => {
        const baseDate = new Date('2024-01-01');
        const snapshots = [
          createSnapshot('s1', new Date(baseDate), 100000, 80000, 100000, 0, 'binance'),
          // $10000 deposit, but total is $111000 -> $1000 profit = 1%
          createSnapshot('s2', new Date(baseDate.getTime() + 86400000), 111000, 90000, 10000, 0, 'binance'),
        ];

        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        await service.generateSignedReport(request);

        // Return should be 1% (adjusted for deposit)
        expect(capturedFinancialData!.dailyReturns[1]!.netReturn).toBeCloseTo(1, 2);
      });
    });

    describe('monthly aggregation', () => {
      it('should correctly aggregate daily returns to monthly', async () => {
        // Create 60 days of data (2 months)
        const snapshots = createMockSnapshots(60);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        await service.generateSignedReport(request);

        expect(capturedFinancialData!.monthlyReturns.length).toBeGreaterThanOrEqual(1);
        // Each monthly return should have the required fields
        capturedFinancialData!.monthlyReturns.forEach(monthly => {
          expect(monthly).toHaveProperty('date');
          expect(monthly).toHaveProperty('netReturn');
          expect(monthly).toHaveProperty('benchmarkReturn');
          expect(monthly).toHaveProperty('outperformance');
          expect(monthly).toHaveProperty('aum');
        });
      });
    });

    describe('metrics calculations', () => {
      it('should calculate positive Sharpe ratio for consistent gains', async () => {
        const baseDate = new Date('2024-01-01');
        const snapshots = [];
        let equity = 100000;

        // Create 30 days with consistent 0.5% daily gains
        for (let i = 0; i < 30; i++) {
          const date = new Date(baseDate);
          date.setDate(date.getDate() + i);
          equity = equity * 1.005;
          snapshots.push({
            id: `snap_${i}`,
            userUid: 'user_test123',
            timestamp: date.toISOString(),
            totalEquity: equity,
            realizedBalance: equity * 0.8,
            unrealizedPnL: equity * 0.02,
            deposits: i === 0 ? 100000 : 0,
            withdrawals: 0,
            exchange: 'binance',
            label: '',
            createdAt: date,
            updatedAt: date,
          });
        }

        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        await service.generateSignedReport(request);

        expect(capturedFinancialData!.metrics.sharpeRatio).toBeGreaterThan(0);
        expect(capturedFinancialData!.metrics.totalReturn).toBeGreaterThan(0);
      });

      it('should calculate max drawdown correctly', async () => {
        const baseDate = new Date('2024-01-01');
        const createSnap = (id: string, timestamp: Date, totalEquity: number, realizedBalance: number, deposits: number, withdrawals: number) => ({
          id, userUid: 'user_test123', timestamp: timestamp.toISOString(), totalEquity, realizedBalance, unrealizedPnL: totalEquity * 0.02, deposits, withdrawals, exchange: 'binance', label: '', createdAt: timestamp, updatedAt: timestamp
        });
        const snapshots = [
          createSnap('s1', new Date(baseDate), 100000, 80000, 100000, 0),
          createSnap('s2', new Date(baseDate.getTime() + 86400000), 110000, 90000, 0, 0),
          // Peak at 110000
          createSnap('s3', new Date(baseDate.getTime() + 2 * 86400000), 99000, 80000, 0, 0),
          // Drawdown of 10%
          createSnap('s4', new Date(baseDate.getTime() + 3 * 86400000), 105000, 85000, 0, 0),
        ];

        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        await service.generateSignedReport(request);

        // Max drawdown should be around 10% (from 110000 to 99000)
        expect(capturedFinancialData!.metrics.maxDrawdown).toBeCloseTo(10, 0);
      });
    });

    describe('currency handling', () => {
      it('should use default USD currency when not specified', async () => {
        const snapshots = createMockSnapshots(10);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        await service.generateSignedReport(request);

        expect(capturedFinancialData!.baseCurrency).toBe('USD');
      });

      it('should use specified currency', async () => {
        const snapshots = createMockSnapshots(10);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        let capturedFinancialData: SignedFinancialData | null = null;
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          capturedFinancialData = data;
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
          baseCurrency: 'EUR',
        };

        await service.generateSignedReport(request);

        expect(capturedFinancialData!.baseCurrency).toBe('EUR');
      });
    });

    describe('report ID generation', () => {
      it('should generate unique report IDs', async () => {
        const snapshots = createMockSnapshots(10);
        mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

        const reportIds: string[] = [];
        mockSigningService.signFinancialData.mockImplementation((data, params) => {
          reportIds.push(data.reportId);
          return createMockSignedReport(data, params);
        });

        const request: ReportRequest = {
          userUid: 'user_test123',
        };

        // Generate multiple reports
        mockReportRepo.findByPeriod.mockResolvedValue(null);
        await service.generateSignedReport(request);
        await service.generateSignedReport(request);

        expect(reportIds[0]).not.toBe(reportIds[1]);
        expect(reportIds[0]).toMatch(/^TR-[a-z0-9]+-[A-F0-9]+$/);
      });
    });
  });
});
