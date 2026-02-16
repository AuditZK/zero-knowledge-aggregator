import { injectable, inject } from 'tsyringe';
import { SnapshotDataRepository } from '../core/repositories/snapshot-data-repository';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('PerformanceMetrics');

/**
 * Daily data point for metrics calculation
 * Aggregated from snapshot data for accurate performance calculations
 */
export interface DailyDataPoint {
  date: Date;
  openEquity: number;
  closeEquity: number;
  highEquity: number;
  lowEquity: number;
  dailyReturnPct: number;
  dailyReturnUsd: number;
  volume: number;
  trades: number;
  fees: number;
}

/**
 * Performance metrics calculated from daily snapshots
 */
export interface PerformanceMetrics {
  // Risk-adjusted returns
  sharpeRatio: number | null;
  sortinoRatio: number | null;
  calmarRatio: number | null;

  // Volatility
  volatility: number | null; // Annualized
  downsideDeviation: number | null;

  // Drawdown
  maxDrawdown: number | null;
  maxDrawdownDuration: number | null; // in days
  currentDrawdown: number | null;

  // Win/Loss
  winRate: number | null;
  profitFactor: number | null;
  avgWin: number | null;
  avgLoss: number | null;

  // Period info
  periodStart: Date;
  periodEnd: Date;
  dataPoints: number;
}

/**
 * Performance Metrics Service
 *
 * SECURITY: Runs inside AMD SEV-SNP enclave
 * - Calculates metrics from aggregated snapshot data only
 * - NO access to individual trades (alpha protection)
 * - Clean code - minimal dependencies for reduced TCB
 *
 * Architecture:
 * - Reads daily snapshots from SnapshotDataRepository
 * - Aggregates snapshots into daily data points
 * - Calculates all performance metrics in-memory
 * - Returns only statistical metrics (no trade details)
 */
@injectable()
export class PerformanceMetricsService {
  constructor(
    @inject(SnapshotDataRepository) private readonly snapshotRepo: SnapshotDataRepository
  ) {}

  /**
   * Calculate all performance metrics for a user
   * Aggregates across all exchanges or filters by specific exchange
   */
  async calculateMetrics(
    userUid: string,
    exchange?: string,
    startDate?: Date,
    endDate?: Date,
    excludedKeys?: Set<string>
  ): Promise<PerformanceMetrics | null> {
    logger.info('Calculating performance metrics', {
      userUid,
      exchange,
      startDate: startDate?.toISOString(),
      endDate: endDate?.toISOString()
    });

    // Fetch snapshots from repository
    const allSnapshots = await this.snapshotRepo.getSnapshotData(
      userUid,
      startDate,
      endDate,
      exchange
    );
    const snapshots = excludedKeys && excludedKeys.size > 0
      ? allSnapshots.filter(s => !excludedKeys.has(s.label ? `${s.exchange}/${s.label}` : s.exchange))
      : allSnapshots;

    if (snapshots.length === 0) {
      logger.warn('No snapshots found for metrics calculation', { userUid, exchange });
      return null;
    }

    // Convert snapshots to daily data points
    const dailyData = this.aggregateToDailyData(snapshots);

    if (dailyData.length < 2) {
      logger.warn('Insufficient data for metrics calculation (need at least 2 days)', {
        userUid,
        exchange,
        dataPoints: dailyData.length
      });
      return null;
    }

    // Calculate all metrics
    const metrics = this.computeMetrics(dailyData);

    logger.info('Performance metrics calculated', {
      userUid,
      exchange,
      sharpeRatio: metrics.sharpeRatio,
      volatility: metrics.volatility,
      maxDrawdown: metrics.maxDrawdown,
      dataPoints: metrics.dataPoints
    });

    return metrics;
  }

  /** Snapshot type for daily aggregation */
  private readonly SnapshotType = {} as {
    timestamp: string;
    totalEquity: number;
    breakdown_by_market?: {
      global?: {
        volume?: number;
        trades?: number;
        trading_fees?: number;
        funding_fees?: number;
      };
    };
  };

  /**
   * Aggregate snapshots into daily data points
   * Handles intraday snapshots by grouping by date (00:00 UTC)
   */
  private aggregateToDailyData(snapshots: Array<typeof this.SnapshotType>): DailyDataPoint[] {
    const byDate = this.groupSnapshotsByDate(snapshots);
    const sortedDates = Array.from(byDate.keys()).sort((a, b) => a.localeCompare(b));

    const dailyData: DailyDataPoint[] = [];
    let previousEquity: number | null = null;

    for (const dateKey of sortedDates) {
      const dataPoint = this.createDailyDataPoint(byDate.get(dateKey)!, dateKey, previousEquity);
      if (dataPoint) {
        dailyData.push(dataPoint);
        previousEquity = dataPoint.closeEquity;
      }
    }

    return dailyData;
  }

  private groupSnapshotsByDate(snapshots: Array<typeof this.SnapshotType>) {
    const byDate = new Map<string, Array<typeof this.SnapshotType>>();

    for (const snapshot of snapshots) {
      const dateKey = new Date(snapshot.timestamp).toISOString().split('T')[0];
      if (!dateKey) continue;

      if (!byDate.has(dateKey)) {
        byDate.set(dateKey, []);
      }
      byDate.get(dateKey)!.push(snapshot);
    }

    return byDate;
  }

  private createDailyDataPoint(
    daySnapshots: Array<typeof this.SnapshotType>,
    dateKey: string,
    previousEquity: number | null
  ): DailyDataPoint | null {
    if (daySnapshots.length === 0) return null;

    // Sum equity across all exchanges for global portfolio view
    // Each day has one snapshot per exchange, all at 00:00 UTC
    const totalEquity = daySnapshots.reduce((sum, s) => sum + s.totalEquity, 0);
    const metrics = this.sumDayMetrics(daySnapshots);

    return {
      date: new Date(dateKey + 'T00:00:00Z'),
      openEquity: totalEquity,
      closeEquity: totalEquity,
      highEquity: totalEquity,
      lowEquity: totalEquity,
      dailyReturnPct: this.calculateReturnPct(totalEquity, previousEquity),
      dailyReturnUsd: previousEquity === null ? 0 : totalEquity - previousEquity,
      ...metrics
    };
  }

  private sumDayMetrics(daySnapshots: Array<typeof this.SnapshotType>) {
    let volume = 0, trades = 0, fees = 0;

    for (const snap of daySnapshots) {
      const global = snap.breakdown_by_market?.global;
      if (!global) continue;

      volume += global.volume || 0;
      trades += global.trades || 0;
      fees += (global.trading_fees || 0) + (global.funding_fees || 0);
    }

    return { volume, trades, fees };
  }

  private calculateReturnPct(closeEquity: number, previousEquity: number | null): number {
    if (previousEquity === null || previousEquity <= 0) return 0;
    return ((closeEquity - previousEquity) / previousEquity) * 100;
  }

  /**
   * Compute all performance metrics from daily data
   */
  private computeMetrics(dailyData: DailyDataPoint[]): PerformanceMetrics {
    if (dailyData.length === 0) {
      throw new Error('Cannot compute metrics from empty daily data');
    }

    // Extract daily returns (skip first day which has 0 return)
    const dailyReturns = dailyData.slice(1).map(d => d.dailyReturnPct);

    // === Core metrics ===
    const volatility = this.calculateVolatility(dailyReturns);
    const annualizedVolatility = volatility * Math.sqrt(252); // 252 trading days

    const avgDailyReturn = dailyReturns.length > 0
      ? dailyReturns.reduce((sum, r) => sum + r, 0) / dailyReturns.length
      : 0;
    const annualizedReturn = avgDailyReturn * 252;

    const sharpeRatio = annualizedVolatility > 0
      ? annualizedReturn / annualizedVolatility
      : 0;

    const maxDrawdown = this.calculateMaxDrawdown(dailyData);
    const winRate = this.calculateWinRate(dailyReturns);

    // === Extended metrics ===

    // Downside deviation (std dev of negative returns only)
    const negativeReturns = dailyReturns.filter(r => r < 0);
    const downsideDeviation = negativeReturns.length > 0
      ? this.calculateVolatility(negativeReturns) * Math.sqrt(252)
      : 0;

    // Sortino Ratio (return / downside deviation)
    const sortinoRatio = downsideDeviation > 0
      ? annualizedReturn / downsideDeviation
      : 0;

    // Calmar Ratio (annualized return / max drawdown)
    const calmarRatio = maxDrawdown > 0
      ? annualizedReturn / maxDrawdown
      : 0;

    // Drawdown details
    const { maxDrawdownDuration, currentDrawdown } = this.calculateDrawdownDetails(dailyData);

    // Profit Factor (sum of gains / sum of losses)
    const gains = dailyReturns.filter(r => r > 0);
    const losses = dailyReturns.filter(r => r < 0);
    const totalGains = gains.reduce((sum, r) => sum + r, 0);
    const totalLosses = Math.abs(losses.reduce((sum, r) => sum + r, 0));

    // Calculate profit factor (sum of gains / sum of losses)
    let profitFactor: number | null;
    if (totalLosses > 0) {
      profitFactor = totalGains / totalLosses;
    } else if (totalGains > 0) {
      profitFactor = null; // infinite profit factor
    } else {
      profitFactor = 0;
    }

    // Average win and loss
    const avgWin = gains.length > 0 ? totalGains / gains.length : 0;
    const avgLoss = losses.length > 0 ? totalLosses / losses.length : 0;

    const firstDay = dailyData[0];
    const lastDay = dailyData.at(-1);

    if (!firstDay || !lastDay) {
      throw new Error('Invalid daily data: missing first or last day');
    }

    return {
      sharpeRatio,
      sortinoRatio,
      calmarRatio,
      volatility: annualizedVolatility,
      downsideDeviation,
      maxDrawdown,
      maxDrawdownDuration,
      currentDrawdown,
      winRate,
      profitFactor,
      avgWin,
      avgLoss,
      periodStart: firstDay.date,
      periodEnd: lastDay.date,
      dataPoints: dailyData.length
    };
  }

  /**
   * Calculate volatility (standard deviation of returns)
   */
  private calculateVolatility(returns: number[]): number {
    if (returns.length === 0) return 0;

    const mean = returns.reduce((sum, r) => sum + r, 0) / returns.length;
    const squaredDiffs = returns.map(r => Math.pow(r - mean, 2));
    const variance = squaredDiffs.reduce((sum, d) => sum + d, 0) / returns.length;

    return Math.sqrt(variance);
  }

  /**
   * Calculate max drawdown from daily equity data
   * Uses high/low equity for accurate intraday drawdown
   */
  private calculateMaxDrawdown(dailyData: DailyDataPoint[]): number {
    if (dailyData.length === 0) return 0;

    const firstDay = dailyData[0];
    if (!firstDay) return 0;

    let peak = Math.max(firstDay.openEquity, firstDay.highEquity);
    let maxDrawdown = 0;

    for (const day of dailyData) {
      // Update peak with the day's high
      if (day.highEquity > peak) {
        peak = day.highEquity;
      }

      // Check drawdown at the day's low
      const drawdownAtLow = ((peak - day.lowEquity) / peak) * 100;
      if (drawdownAtLow > maxDrawdown) {
        maxDrawdown = drawdownAtLow;
      }

      // Also check drawdown at close
      const drawdownAtClose = ((peak - day.closeEquity) / peak) * 100;
      if (drawdownAtClose > maxDrawdown) {
        maxDrawdown = drawdownAtClose;
      }
    }

    return maxDrawdown;
  }

  /**
   * Calculate win rate (% of positive days)
   */
  private calculateWinRate(returns: number[]): number {
    if (returns.length === 0) return 0;

    const wins = returns.filter(r => r > 0).length;
    return (wins / returns.length) * 100;
  }

  /**
   * Calculate max drawdown duration (in days) and current drawdown
   */
  private calculateDrawdownDetails(dailyData: DailyDataPoint[]): {
    maxDrawdownDuration: number;
    currentDrawdown: number;
  } {
    const firstDay = dailyData[0];
    if (!firstDay) {
      return { maxDrawdownDuration: 0, currentDrawdown: 0 };
    }

    const state = this.initDrawdownState(firstDay);

    for (const day of dailyData) {
      this.updateDrawdownState(state, day);
    }

    return this.finalizeDrawdownResult(state, dailyData.at(-1));
  }

  private initDrawdownState(firstDay: DailyDataPoint) {
    return {
      peak: firstDay.closeEquity,
      peakDate: firstDay.date,
      maxDrawdownDuration: 0,
      currentDrawdownStart: null as Date | null
    };
  }

  private updateDrawdownState(
    state: { peak: number; peakDate: Date; maxDrawdownDuration: number; currentDrawdownStart: Date | null },
    day: DailyDataPoint
  ) {
    if (day.closeEquity >= state.peak) {
      // New peak reached - end of drawdown period
      state.maxDrawdownDuration = this.updateMaxDuration(
        state.maxDrawdownDuration,
        state.currentDrawdownStart,
        day.date
      );
      state.currentDrawdownStart = null;
      state.peak = day.closeEquity;
      state.peakDate = day.date;
    } else {
      // Entering drawdown (if not already in one)
      state.currentDrawdownStart ??= state.peakDate;
    }
  }

  private updateMaxDuration(currentMax: number, startDate: Date | null, endDate: Date): number {
    if (!startDate) return currentMax;
    const duration = this.daysBetween(startDate, endDate);
    return Math.max(currentMax, duration);
  }

  private daysBetween(start: Date, end: Date): number {
    return Math.floor((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
  }

  private finalizeDrawdownResult(
    state: { peak: number; maxDrawdownDuration: number; currentDrawdownStart: Date | null },
    lastDay: DailyDataPoint | undefined
  ) {
    if (!lastDay) {
      return { maxDrawdownDuration: state.maxDrawdownDuration, currentDrawdown: 0 };
    }

    const currentDrawdown = state.peak > 0
      ? ((state.peak - lastDay.closeEquity) / state.peak) * 100
      : 0;

    const maxDrawdownDuration = this.updateMaxDuration(
      state.maxDrawdownDuration,
      state.currentDrawdownStart,
      lastDay.date
    );

    return { maxDrawdownDuration, currentDrawdown };
  }
}
