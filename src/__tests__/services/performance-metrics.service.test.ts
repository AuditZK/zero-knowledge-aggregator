import { PerformanceMetricsService } from '../../services/performance-metrics.service';
import type { SnapshotDataRepository } from '../../core/repositories/snapshot-data-repository';
import type { SnapshotData } from '../../types';

describe('PerformanceMetricsService', () => {
  let service: PerformanceMetricsService;
  let mockSnapshotRepo: jest.Mocked<SnapshotDataRepository>;

  // Counter for unique IDs
  let snapshotIdCounter = 0;

  // Helper to create snapshot data with all required fields
  const createSnapshot = (timestamp: string, totalEquity: number, extraData?: {
    volume?: number;
    trades?: number;
    tradingFees?: number;
    fundingFees?: number;
  }): SnapshotData => ({
    id: `snapshot-${++snapshotIdCounter}`,
    userUid: 'user123',
    timestamp,
    exchange: 'test-exchange',
    label: 'test-exchange account',
    totalEquity,
    realizedBalance: totalEquity * 0.8,
    unrealizedPnL: totalEquity * 0.2,
    deposits: 0,
    withdrawals: 0,
    createdAt: new Date(timestamp),
    updatedAt: new Date(timestamp),
    breakdown_by_market: extraData ? {
      global: {
        totalEquityUsd: totalEquity,
        unrealizedPnl: totalEquity * 0.2,
        volume: extraData.volume ?? 0,
        trades: extraData.trades ?? 0,
        tradingFees: extraData.tradingFees ?? 0,
        fundingFees: extraData.fundingFees ?? 0,
      }
    } : undefined
  });

  beforeEach(() => {
    mockSnapshotRepo = {
      getSnapshotData: jest.fn(),
      createSnapshot: jest.fn(),
      getLatestSnapshot: jest.fn(),
      getSnapshotsByDateRange: jest.fn(),
      deleteOldSnapshots: jest.fn(),
    } as unknown as jest.Mocked<SnapshotDataRepository>;

    service = new PerformanceMetricsService(mockSnapshotRepo);
  });

  describe('calculateMetrics', () => {
    it('should return null when no snapshots found', async () => {
      mockSnapshotRepo.getSnapshotData.mockResolvedValue([]);

      const result = await service.calculateMetrics('user123');

      expect(result).toBeNull();
    });

    it('should return null when only one day of data', async () => {
      mockSnapshotRepo.getSnapshotData.mockResolvedValue([
        createSnapshot('2024-01-01T12:00:00Z', 10000),
      ]);

      const result = await service.calculateMetrics('user123');

      expect(result).toBeNull();
    });

    it('should calculate metrics with valid data', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10100),
        createSnapshot('2024-01-03T12:00:00Z', 10200),
        createSnapshot('2024-01-04T12:00:00Z', 10300),
        createSnapshot('2024-01-05T12:00:00Z', 10400),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.dataPoints).toBe(5);
      expect(result?.periodStart).toBeInstanceOf(Date);
      expect(result?.periodEnd).toBeInstanceOf(Date);
    });

    it('should pass exchange filter to repository', async () => {
      mockSnapshotRepo.getSnapshotData.mockResolvedValue([]);

      await service.calculateMetrics('user123', 'binance');

      expect(mockSnapshotRepo.getSnapshotData).toHaveBeenCalledWith(
        'user123',
        undefined,
        undefined,
        'binance'
      );
    });

    it('should pass date range to repository', async () => {
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');
      mockSnapshotRepo.getSnapshotData.mockResolvedValue([]);

      await service.calculateMetrics('user123', undefined, startDate, endDate);

      expect(mockSnapshotRepo.getSnapshotData).toHaveBeenCalledWith(
        'user123',
        startDate,
        endDate,
        undefined
      );
    });
  });

  describe('metrics calculations', () => {
    it('should calculate positive returns correctly', async () => {
      // 5 days with steady 1% daily growth
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10100),
        createSnapshot('2024-01-03T12:00:00Z', 10201),
        createSnapshot('2024-01-04T12:00:00Z', 10303),
        createSnapshot('2024-01-05T12:00:00Z', 10406),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.winRate).toBe(100); // All positive days
      expect(result?.maxDrawdown).toBe(0); // No drawdown
    });

    it('should calculate negative returns correctly', async () => {
      // 5 days with steady decline
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 9900),
        createSnapshot('2024-01-03T12:00:00Z', 9800),
        createSnapshot('2024-01-04T12:00:00Z', 9700),
        createSnapshot('2024-01-05T12:00:00Z', 9600),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.winRate).toBe(0); // All negative days
      expect(result?.maxDrawdown).toBeGreaterThan(0); // Has drawdown
    });

    it('should calculate mixed returns correctly', async () => {
      // Mix of up and down days
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10200), // +2%
        createSnapshot('2024-01-03T12:00:00Z', 10100), // -1%
        createSnapshot('2024-01-04T12:00:00Z', 10400), // +3%
        createSnapshot('2024-01-05T12:00:00Z', 10300), // -1%
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.winRate).toBe(50); // 2 wins, 2 losses
    });

    it('should calculate volatility', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10500), // +5%
        createSnapshot('2024-01-03T12:00:00Z', 9975), // -5%
        createSnapshot('2024-01-04T12:00:00Z', 10473), // +5%
        createSnapshot('2024-01-05T12:00:00Z', 9949), // -5%
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.volatility).toBeGreaterThan(0);
    });

    it('should calculate Sharpe ratio', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10100),
        createSnapshot('2024-01-03T12:00:00Z', 10200),
        createSnapshot('2024-01-04T12:00:00Z', 10300),
        createSnapshot('2024-01-05T12:00:00Z', 10400),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(typeof result?.sharpeRatio).toBe('number');
    });

    it('should calculate Sortino ratio', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10100),
        createSnapshot('2024-01-03T12:00:00Z', 10000), // down day for downside deviation
        createSnapshot('2024-01-04T12:00:00Z', 10150),
        createSnapshot('2024-01-05T12:00:00Z', 10200),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(typeof result?.sortinoRatio).toBe('number');
    });

    it('should calculate max drawdown', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 11000), // Peak
        createSnapshot('2024-01-03T12:00:00Z', 9900),  // -10% from peak
        createSnapshot('2024-01-04T12:00:00Z', 10500), // Recovery
        createSnapshot('2024-01-05T12:00:00Z', 11200), // New peak
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.maxDrawdown).toBeGreaterThan(0);
      // Max drawdown should be approximately 10% (11000 -> 9900)
      expect(result?.maxDrawdown).toBeCloseTo(10, 0);
    });

    it('should calculate profit factor', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10300), // +3%
        createSnapshot('2024-01-03T12:00:00Z', 10200), // -1%
        createSnapshot('2024-01-04T12:00:00Z', 10500), // +3%
        createSnapshot('2024-01-05T12:00:00Z', 10400), // -1%
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.profitFactor).toBeGreaterThan(1); // More gains than losses
    });

    it('should handle profit factor with no losses', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10100),
        createSnapshot('2024-01-03T12:00:00Z', 10200),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      // Profit factor is null when no losses (infinite)
      expect(result?.profitFactor).toBeNull();
    });

    it('should calculate average win and loss', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10200), // +2%
        createSnapshot('2024-01-03T12:00:00Z', 10100), // -1%
        createSnapshot('2024-01-04T12:00:00Z', 10300), // +2%
        createSnapshot('2024-01-05T12:00:00Z', 10200), // -1%
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.avgWin).toBeGreaterThan(0);
      expect(result?.avgLoss).toBeGreaterThan(0);
    });
  });

  describe('daily data aggregation', () => {
    it('should aggregate multiple intraday snapshots', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T09:00:00Z', 10000),
        createSnapshot('2024-01-01T12:00:00Z', 10100),
        createSnapshot('2024-01-01T15:00:00Z', 10050),
        createSnapshot('2024-01-02T09:00:00Z', 10100),
        createSnapshot('2024-01-02T15:00:00Z', 10150),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.dataPoints).toBe(2); // 2 days
    });

    it('should track high and low equity for drawdown', async () => {
      const snapshots = [
        // Day 1: High of 10500, Low of 10000
        createSnapshot('2024-01-01T09:00:00Z', 10000),
        createSnapshot('2024-01-01T12:00:00Z', 10500),
        createSnapshot('2024-01-01T15:00:00Z', 10200),
        // Day 2: Drawdown
        createSnapshot('2024-01-02T09:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 9500), // Low
        createSnapshot('2024-01-02T15:00:00Z', 9800),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      // Max drawdown from 10500 (day 1 high) to 9500 (day 2 low) = ~9.5%
      expect(result?.maxDrawdown).toBeGreaterThan(9);
    });

    it('should aggregate trading metrics', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000, {
          volume: 1000,
          trades: 5,
          tradingFees: 10,
          fundingFees: 2,
        }),
        createSnapshot('2024-01-02T12:00:00Z', 10100, {
          volume: 2000,
          trades: 10,
          tradingFees: 20,
          fundingFees: 4,
        }),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
    });
  });

  describe('edge cases', () => {
    it('should handle zero equity gracefully', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 0),
        createSnapshot('2024-01-02T12:00:00Z', 100),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
    });

    it('should handle very large equity values', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 1_000_000_000),
        createSnapshot('2024-01-02T12:00:00Z', 1_010_000_000),
        createSnapshot('2024-01-03T12:00:00Z', 1_020_000_000),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.dataPoints).toBe(3);
    });

    it('should handle snapshots missing breakdown data', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10100),
      ];
      // Remove breakdown data
      if (snapshots[0]) snapshots[0].breakdown_by_market = undefined;
      if (snapshots[1]) snapshots[1].breakdown_by_market = undefined;
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
    });

    it('should handle flat returns (no change)', async () => {
      const snapshots = [
        createSnapshot('2024-01-01T12:00:00Z', 10000),
        createSnapshot('2024-01-02T12:00:00Z', 10000),
        createSnapshot('2024-01-03T12:00:00Z', 10000),
      ];
      mockSnapshotRepo.getSnapshotData.mockResolvedValue(snapshots);

      const result = await service.calculateMetrics('user123');

      expect(result).not.toBeNull();
      expect(result?.volatility).toBe(0);
      expect(result?.maxDrawdown).toBe(0);
    });
  });
});
