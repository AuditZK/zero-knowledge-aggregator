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
    endDate?: Date
  ): Promise<PerformanceMetrics | null> {
    logger.info('Calculating performance metrics', {
      userUid,
      exchange,
      startDate: startDate?.toISOString(),
      endDate: endDate?.toISOString()
    });

    // Fetch snapshots from repository
    const snapshots = await this.snapshotRepo.getSnapshotData(
      userUid,
      startDate,
      endDate,
      exchange
    );

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

  /**
   * Aggregate snapshots into daily data points
   * Handles intraday snapshots by grouping by date (00:00 UTC)
   */
  private aggregateToDailyData(snapshots: Array<{
    timestamp: string;
    totalEquity: number;
    breakdown_by_market?: {
      global?: {
        volume?: number;
        orders?: number;
        trading_fees?: number;
        funding_fees?: number;
      };
    };
  }>): DailyDataPoint[] {
    // Group snapshots by date (YYYY-MM-DD)
    const byDate = new Map<string, typeof snapshots>();

    for (const snapshot of snapshots) {
      const dateKey = new Date(snapshot.timestamp).toISOString().split('T')[0];
      if (!dateKey) continue; // Skip invalid dates

      if (!byDate.has(dateKey)) {
        byDate.set(dateKey, []);
      }
      byDate.get(dateKey)!.push(snapshot);
    }

    const dailyData: DailyDataPoint[] = [];
    let previousEquity: number | null = null;

    // Sort dates chronologically
    const sortedDates = Array.from(byDate.keys()).sort();

    for (const dateKey of sortedDates) {
      const daySnapshots = byDate.get(dateKey);
      if (!daySnapshots || daySnapshots.length === 0) continue;

      daySnapshots.sort((a, b) =>
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );

      // Open = first snapshot, Close = last snapshot
      const openSnap = daySnapshots[0];
      const closeSnap = daySnapshots[daySnapshots.length - 1];

      if (!openSnap || !closeSnap) continue;

      // Extract metrics from breakdown
      const equities = daySnapshots.map(s => s.totalEquity);
      const highEquity = Math.max(...equities);
      const lowEquity = Math.min(...equities);

      // Sum volume, trades, fees for the day
      let totalVolume = 0;
      let totalTrades = 0;
      let totalFees = 0;

      for (const snap of daySnapshots) {
        const breakdown = snap.breakdown_by_market;
        if (breakdown?.global) {
          totalVolume += breakdown.global.volume || 0;
          totalTrades += breakdown.global.orders || 0;
          totalFees += (breakdown.global.trading_fees || 0) + (breakdown.global.funding_fees || 0);
        }
      }

      // Calculate daily return
      const dailyReturnPct = previousEquity !== null && previousEquity > 0
        ? ((closeSnap.totalEquity - previousEquity) / previousEquity) * 100
        : 0;

      const dailyReturnUsd = previousEquity !== null
        ? closeSnap.totalEquity - previousEquity
        : 0;

      dailyData.push({
        date: new Date(dateKey + 'T00:00:00Z'),
        openEquity: openSnap.totalEquity,
        closeEquity: closeSnap.totalEquity,
        highEquity,
        lowEquity,
        dailyReturnPct,
        dailyReturnUsd,
        volume: totalVolume,
        trades: totalTrades,
        fees: totalFees
      });

      previousEquity = closeSnap.totalEquity;
    }

    return dailyData;
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
    const profitFactor = totalLosses > 0
      ? totalGains / totalLosses
      : (totalGains > 0 ? null : 0); // null = infinite profit factor

    // Average win and loss
    const avgWin = gains.length > 0 ? totalGains / gains.length : 0;
    const avgLoss = losses.length > 0 ? totalLosses / losses.length : 0;

    const firstDay = dailyData[0];
    const lastDay = dailyData[dailyData.length - 1];

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
    if (dailyData.length === 0) {
      return { maxDrawdownDuration: 0, currentDrawdown: 0 };
    }

    const firstDay = dailyData[0];
    if (!firstDay) {
      return { maxDrawdownDuration: 0, currentDrawdown: 0 };
    }

    let peak = firstDay.closeEquity;
    let peakDate = firstDay.date;
    let maxDrawdownDuration = 0;
    let currentDrawdownStart: Date | null = null;

    for (const day of dailyData) {
      if (day.closeEquity >= peak) {
        // New peak reached - end of drawdown period
        if (currentDrawdownStart) {
          const duration = Math.floor(
            (day.date.getTime() - currentDrawdownStart.getTime()) / (1000 * 60 * 60 * 24)
          );
          if (duration > maxDrawdownDuration) {
            maxDrawdownDuration = duration;
          }
          currentDrawdownStart = null;
        }
        peak = day.closeEquity;
        peakDate = day.date;
      } else {
        // In drawdown
        if (!currentDrawdownStart) {
          currentDrawdownStart = peakDate;
        }
      }
    }

    // Check if we're still in a drawdown at the end
    const lastDay = dailyData[dailyData.length - 1];
    if (!lastDay) {
      return { maxDrawdownDuration, currentDrawdown: 0 };
    }

    const currentDrawdown = peak > 0
      ? ((peak - lastDay.closeEquity) / peak) * 100
      : 0;

    // If still in drawdown, calculate current duration
    if (currentDrawdownStart) {
      const currentDuration = Math.floor(
        (lastDay.date.getTime() - currentDrawdownStart.getTime()) / (1000 * 60 * 60 * 24)
      );
      if (currentDuration > maxDrawdownDuration) {
        maxDrawdownDuration = currentDuration;
      }
    }

    return { maxDrawdownDuration, currentDrawdown };
  }
}
