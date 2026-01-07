import { injectable, inject } from 'tsyringe';
import { randomBytes } from 'crypto';
import { SnapshotDataRepository } from '../core/repositories/snapshot-data-repository';
import { ReportSigningService } from './report-signing.service';
import { getLogger } from '../utils/secure-enclave-logger';
import {
  ReportRequest,
  ReportData,
  ReportMetrics,
  CoreMetrics,
  RiskMetrics,
  BenchmarkMetrics,
  DrawdownData,
  DrawdownPeriod,
  DailyReturn,
  MonthlyReturn,
  GenerateReportResult
} from '../types/report.types';

const logger = getLogger('ReportGenerator');

// Constants
const TRADING_DAYS_PER_YEAR = 252;
// NOTE: Risk-free rate set to 0 to align with Analytics Service calculations
const RISK_FREE_RATE = 0;

/**
 * Report Generator Service
 *
 * SECURITY: Runs inside AMD SEV-SNP enclave
 * - Calculates all performance metrics from aggregated snapshot data
 * - NO access to individual trades (alpha protection)
 * - Signs reports with enclave key for authenticity
 *
 * Flow:
 * 1. Fetch snapshots from SnapshotDataRepository
 * 2. Convert to daily returns
 * 3. Calculate all metrics
 * 4. Optionally fetch and calculate benchmark metrics
 * 5. Sign the report
 */
@injectable()
export class ReportGeneratorService {
  constructor(
    @inject(SnapshotDataRepository) private readonly snapshotRepo: SnapshotDataRepository,
    @inject(ReportSigningService) private readonly signingService: ReportSigningService
  ) {}

  /**
   * Generate a signed track record report
   */
  async generateSignedReport(request: ReportRequest): Promise<GenerateReportResult> {
    try {
      logger.info('Generating signed report', {
        userUid: request.userUid,
        startDate: request.startDate,
        endDate: request.endDate,
        benchmark: request.benchmark
      });

      // 1. Fetch snapshots from database
      const snapshots = await this.snapshotRepo.getSnapshotData(
        request.userUid,
        request.startDate ? new Date(request.startDate) : undefined,
        request.endDate ? new Date(request.endDate) : undefined
      );

      if (snapshots.length === 0) {
        return {
          success: false,
          error: 'No snapshot data found for the specified period'
        };
      }

      // 2. Convert snapshots to daily returns
      const dailyReturns = this.convertSnapshotsToDailyReturns(snapshots);

      if (dailyReturns.length < 2) {
        return {
          success: false,
          error: 'Insufficient data for report generation (need at least 2 days)'
        };
      }

      // 3. Aggregate to monthly returns
      const monthlyReturns = this.aggregateToMonthlyReturns(dailyReturns);

      // 4. Calculate core metrics
      const coreMetrics = this.calculateCoreMetrics(dailyReturns);

      // 5. Calculate optional metrics
      const metrics: ReportMetrics = { ...coreMetrics };

      if (request.includeRiskMetrics) {
        metrics.riskMetrics = this.calculateRiskMetrics(dailyReturns);
      }

      if (request.includeDrawdown) {
        metrics.drawdownData = this.calculateDrawdownData(dailyReturns);
      }

      // 6. Calculate benchmark metrics if requested
      if (request.benchmark) {
        const firstDay = dailyReturns[0];
        const lastDay = dailyReturns[dailyReturns.length - 1];

        if (!firstDay || !lastDay) {
          return {
            success: false,
            error: 'Invalid daily returns data'
          };
        }

        const benchmarkReturns = await this.fetchBenchmarkReturns(
          request.benchmark,
          firstDay.date,
          lastDay.date
        );

        if (benchmarkReturns.length > 0) {
          // Create a map for fast date-based lookup
          const benchmarkMap = new Map(benchmarkReturns.map(b => [b.date, b.return]));

          // Merge benchmark returns with daily returns
          const mergedReturns = this.mergeBenchmarkReturns(dailyReturns, benchmarkReturns);
          metrics.benchmarkMetrics = this.calculateBenchmarkMetrics(mergedReturns);

          // Update daily returns with benchmark data (by date, not by index)
          dailyReturns.forEach((dr) => {
            const benchReturn = benchmarkMap.get(dr.date);
            if (benchReturn !== undefined) {
              dr.benchmarkReturn = benchReturn;
              dr.outperformance = dr.netReturn - benchReturn;
            }
          });
        }
      }

      // 7. Build report data
      const reportFirstDay = dailyReturns[0];
      const reportLastDay = dailyReturns[dailyReturns.length - 1];

      if (!reportFirstDay || !reportLastDay) {
        return {
          success: false,
          error: 'Invalid daily returns data for report'
        };
      }

      const reportData: ReportData = {
        reportId: this.generateReportId(),
        userUid: request.userUid,
        reportName: request.reportName || 'Track Record Report',
        generatedAt: new Date(),
        periodStart: new Date(reportFirstDay.date),
        periodEnd: new Date(reportLastDay.date),
        baseCurrency: request.baseCurrency || 'USD',
        benchmark: request.benchmark,
        dataPoints: dailyReturns.length,
        metrics,
        dailyReturns,
        monthlyReturns
      };

      // 8. Sign the report
      const signedReport = this.signingService.signReport(reportData);

      logger.info('Signed report generated successfully', {
        reportId: reportData.reportId,
        dataPoints: reportData.dataPoints,
        periodStart: reportData.periodStart.toISOString(),
        periodEnd: reportData.periodEnd.toISOString()
      });

      return {
        success: true,
        signedReport
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error('Failed to generate signed report', { error: errorMessage });

      return {
        success: false,
        error: errorMessage
      };
    }
  }

  /**
   * Generate unique report ID
   */
  private generateReportId(): string {
    const timestamp = Date.now().toString(36);
    const random = randomBytes(4).toString('hex').toUpperCase();
    return `TR-${timestamp}-${random}`;
  }

  /**
   * Convert snapshot data to daily returns
   * ALIGNED with Analytics Service TWR (Time-Weighted Return) calculation
   *
   * MULTI-EXCHANGE SUPPORT:
   * - Groups snapshots by date AND exchange
   * - Aggregates equity across all exchanges for each day
   * - Handles new exchanges appearing (treats initial equity as deposit)
   */
  private convertSnapshotsToDailyReturns(snapshots: Array<{
    timestamp: string;
    totalEquity: number;
    realizedBalance: number;
    deposits: number;
    withdrawals: number;
    exchange?: string;
  }>): DailyReturn[] {
    // Group snapshots by date AND exchange
    // Map<dateKey, Map<exchange, snapshot[]>>
    const byDateAndExchange = new Map<string, Map<string, typeof snapshots>>();

    for (const snapshot of snapshots) {
      const dateKey = new Date(snapshot.timestamp).toISOString().split('T')[0];
      if (!dateKey) continue;

      const exchange = snapshot.exchange || 'unknown';

      if (!byDateAndExchange.has(dateKey)) {
        byDateAndExchange.set(dateKey, new Map());
      }
      const exchangeMap = byDateAndExchange.get(dateKey)!;

      if (!exchangeMap.has(exchange)) {
        exchangeMap.set(exchange, []);
      }
      exchangeMap.get(exchange)!.push(snapshot);
    }

    const dailyReturns: DailyReturn[] = [];
    let previousCloseEquity: number | null = null;
    let cumulativeReturn = 1.0;

    // Track seen exchanges and their last known equity (for forward-fill)
    const seenExchanges = new Set<string>();
    const lastKnownEquity = new Map<string, number>();
    const exchangeFirstEquity = new Map<string, number>();

    // Sort dates chronologically
    const sortedDates = Array.from(byDateAndExchange.keys()).sort();
    const isFirstDay = (dateKey: string) => dateKey === sortedDates[0];

    // Find first equity for each exchange
    for (const dateKey of sortedDates) {
      const exchangeMap = byDateAndExchange.get(dateKey)!;
      for (const [exchange, daySnapshots] of exchangeMap.entries()) {
        if (!exchangeFirstEquity.has(exchange) && daySnapshots.length > 0) {
          const sorted = [...daySnapshots].sort((a, b) =>
            new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
          );
          exchangeFirstEquity.set(exchange, sorted[0]!.totalEquity);
        }
      }
    }

    for (const dateKey of sortedDates) {
      const exchangeMap = byDateAndExchange.get(dateKey)!;

      // Aggregate equity, deposits, withdrawals across ALL exchanges for this day
      let totalEquity = 0;
      let totalDeposits = 0;
      let totalWithdrawals = 0;
      let virtualDeposit = 0;

      // First, add data from exchanges that have snapshots today
      for (const [exchange, daySnapshots] of exchangeMap.entries()) {
        // Sort and take last snapshot of the day for this exchange
        const sorted = [...daySnapshots].sort((a, b) =>
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
        );
        const closeSnap = sorted[sorted.length - 1]!;

        totalEquity += closeSnap.totalEquity;
        totalDeposits += closeSnap.deposits;
        totalWithdrawals += closeSnap.withdrawals;

        // Update last known equity for this exchange
        lastKnownEquity.set(exchange, closeSnap.totalEquity);

        // Check if this is a NEW exchange appearing after the first day
        if (!seenExchanges.has(exchange)) {
          seenExchanges.add(exchange);
          if (!isFirstDay(dateKey)) {
            // New exchange after first day - treat initial equity as virtual deposit
            const firstEquity = exchangeFirstEquity.get(exchange) || closeSnap.totalEquity;
            virtualDeposit += firstEquity;
          }
        }
      }

      // Forward-fill: add last known equity for exchanges not present today
      for (const [exchange, equity] of lastKnownEquity.entries()) {
        if (!exchangeMap.has(exchange)) {
          totalEquity += equity;
        }
      }

      // TWR formula aligned with Analytics:
      const netDeposits = totalDeposits - totalWithdrawals + virtualDeposit;

      let dailyReturnPct = 0;
      if (previousCloseEquity !== null && previousCloseEquity > 0) {
        const adjustedReturn = totalEquity - previousCloseEquity - netDeposits;
        dailyReturnPct = (adjustedReturn / previousCloseEquity) * 100;
        cumulativeReturn *= (1 + dailyReturnPct / 100);
      }

      dailyReturns.push({
        date: dateKey,
        netReturn: dailyReturnPct,
        benchmarkReturn: 0,
        outperformance: dailyReturnPct,
        cumulativeReturn,
        nav: totalEquity
      });

      previousCloseEquity = totalEquity;
    }

    return dailyReturns;
  }

  /**
   * Aggregate daily returns to monthly
   */
  private aggregateToMonthlyReturns(dailyReturns: DailyReturn[]): MonthlyReturn[] {
    const monthlyMap = new Map<string, DailyReturn[]>();

    for (const daily of dailyReturns) {
      const monthKey = daily.date.substring(0, 7); // YYYY-MM
      if (!monthlyMap.has(monthKey)) {
        monthlyMap.set(monthKey, []);
      }
      monthlyMap.get(monthKey)!.push(daily);
    }

    const monthlyReturns: MonthlyReturn[] = [];

    monthlyMap.forEach((dailyData, monthKey) => {
      if (dailyData.length === 0) return;

      const sortedData = dailyData.sort((a, b) => a.date.localeCompare(b.date));
      const firstDay = sortedData[0];
      const lastDay = sortedData[sortedData.length - 1];

      if (!firstDay || !lastDay) return;

      // Calculate compounded monthly return
      const monthlyReturn = (lastDay.cumulativeReturn / firstDay.cumulativeReturn) - 1;

      // Calculate benchmark monthly return if available
      const benchmarkDailyReturns = sortedData.map(d => d.benchmarkReturn / 100);
      let monthlyBenchmark = 0;
      if (benchmarkDailyReturns.some(r => r !== 0)) {
        monthlyBenchmark = (benchmarkDailyReturns.reduce((acc, r) => acc * (1 + r), 1) - 1) * 100;
      }

      monthlyReturns.push({
        date: monthKey,
        netReturn: monthlyReturn * 100,
        benchmarkReturn: monthlyBenchmark,
        outperformance: (monthlyReturn * 100) - monthlyBenchmark,
        aum: lastDay.nav
      });
    });

    return monthlyReturns.sort((a, b) => a.date.localeCompare(b.date));
  }

  /**
   * Calculate core performance metrics
   */
  private calculateCoreMetrics(dailyReturns: DailyReturn[]): CoreMetrics {
    const returns = dailyReturns.map(d => d.netReturn / 100);

    // Total return
    const lastDay = dailyReturns[dailyReturns.length - 1];
    const totalReturn = lastDay ? (lastDay.cumulativeReturn - 1) * 100 : 0;

    // Annualized return
    const years = dailyReturns.length / TRADING_DAYS_PER_YEAR;
    const annualizedReturn = years > 0
      ? (Math.pow(1 + totalReturn / 100, 1 / years) - 1) * 100
      : 0;

    // Volatility (annualized)
    const volatility = this.calculateVolatility(returns) * Math.sqrt(TRADING_DAYS_PER_YEAR) * 100;

    // Sharpe Ratio
    const excessReturn = annualizedReturn - RISK_FREE_RATE;
    const sharpeRatio = volatility > 0 ? excessReturn / volatility : 0;

    // Sortino Ratio (using downside deviation)
    const downsideDeviation = this.calculateDownsideDeviation(returns) * Math.sqrt(TRADING_DAYS_PER_YEAR) * 100;
    const sortinoRatio = downsideDeviation > 0 ? excessReturn / downsideDeviation : 0;

    // Max Drawdown
    const maxDrawdown = this.calculateMaxDrawdown(dailyReturns);

    // Calmar Ratio (maxDrawdown is now positive, aligned with Analytics)
    const calmarRatio = maxDrawdown > 0 ? annualizedReturn / maxDrawdown : 0;

    return {
      totalReturn,
      annualizedReturn,
      volatility,
      sharpeRatio,
      sortinoRatio,
      maxDrawdown,
      calmarRatio
    };
  }

  /**
   * Calculate risk metrics
   */
  private calculateRiskMetrics(dailyReturns: DailyReturn[]): RiskMetrics {
    const returns = dailyReturns.map(d => d.netReturn);
    const sortedReturns = [...returns].sort((a, b) => a - b);

    // VaR calculations
    const var95Index = Math.max(0, Math.floor(returns.length * 0.05));
    const var99Index = Math.max(0, Math.floor(returns.length * 0.01));

    const var95 = sortedReturns[var95Index] || 0;
    const var99 = sortedReturns[var99Index] || 0;

    // Expected Shortfall (CVaR) - average of returns below VaR
    const tailReturns = sortedReturns.slice(0, var95Index + 1);
    const expectedShortfall = tailReturns.length > 0
      ? tailReturns.reduce((sum, r) => sum + r, 0) / tailReturns.length
      : 0;

    // Higher moments
    const mean = returns.reduce((sum, r) => sum + r, 0) / returns.length;
    const variance = returns.reduce((sum, r) => sum + Math.pow(r - mean, 2), 0) / returns.length;
    const stdDev = Math.sqrt(variance);

    // Skewness
    const skewness = stdDev > 0
      ? returns.reduce((sum, r) => sum + Math.pow((r - mean) / stdDev, 3), 0) / returns.length
      : 0;

    // Kurtosis (excess)
    const kurtosis = stdDev > 0
      ? returns.reduce((sum, r) => sum + Math.pow((r - mean) / stdDev, 4), 0) / returns.length - 3
      : 0;

    return {
      var95,
      var99,
      expectedShortfall,
      skewness,
      kurtosis
    };
  }

  /**
   * Calculate benchmark-relative metrics
   */
  private calculateBenchmarkMetrics(mergedReturns: Array<{
    portfolioReturn: number;
    benchmarkReturn: number;
    date: string;
  }>): BenchmarkMetrics {
    if (mergedReturns.length < 30) {
      return { alpha: 0, beta: 0, informationRatio: 0, trackingError: 0, correlation: 0 };
    }

    const portfolioReturns = mergedReturns.map(d => d.portfolioReturn);
    const benchmarkReturns = mergedReturns.map(d => d.benchmarkReturn);

    // Calculate means
    const portfolioMean = portfolioReturns.reduce((sum, r) => sum + r, 0) / portfolioReturns.length;
    const benchmarkMean = benchmarkReturns.reduce((sum, r) => sum + r, 0) / benchmarkReturns.length;

    // Calculate covariance and variances
    let covariance = 0;
    let portfolioVariance = 0;
    let benchmarkVariance = 0;

    for (let i = 0; i < mergedReturns.length; i++) {
      const portfolioVal = portfolioReturns[i];
      const benchmarkVal = benchmarkReturns[i];

      if (portfolioVal === undefined || benchmarkVal === undefined) continue;

      const portfolioDiff = portfolioVal - portfolioMean;
      const benchmarkDiff = benchmarkVal - benchmarkMean;

      covariance += portfolioDiff * benchmarkDiff;
      portfolioVariance += portfolioDiff * portfolioDiff;
      benchmarkVariance += benchmarkDiff * benchmarkDiff;
    }

    covariance /= (mergedReturns.length - 1);
    portfolioVariance /= (mergedReturns.length - 1);
    benchmarkVariance /= (mergedReturns.length - 1);

    // Beta
    const beta = benchmarkVariance > 0 ? covariance / benchmarkVariance : 0;

    // Alpha (CAPM)
    const portfolioAnnualReturn = portfolioMean * TRADING_DAYS_PER_YEAR * 100;
    const benchmarkAnnualReturn = benchmarkMean * TRADING_DAYS_PER_YEAR * 100;
    const expectedReturn = RISK_FREE_RATE + beta * (benchmarkAnnualReturn - RISK_FREE_RATE);
    const alpha = portfolioAnnualReturn - expectedReturn;

    // Correlation
    const portfolioStd = Math.sqrt(portfolioVariance);
    const benchmarkStd = Math.sqrt(benchmarkVariance);
    const correlation = (portfolioStd > 0 && benchmarkStd > 0)
      ? covariance / (portfolioStd * benchmarkStd)
      : 0;

    // Tracking Error
    const activeReturns = mergedReturns.map((_, i) => {
      const pReturn = portfolioReturns[i] ?? 0;
      const bReturn = benchmarkReturns[i] ?? 0;
      return pReturn - bReturn;
    });
    const activeReturnMean = activeReturns.reduce((sum, r) => sum + r, 0) / activeReturns.length;
    const trackingErrorVariance = activeReturns.reduce((sum, r) =>
      sum + Math.pow(r - activeReturnMean, 2), 0) / (activeReturns.length - 1);
    const trackingError = Math.sqrt(trackingErrorVariance) * Math.sqrt(TRADING_DAYS_PER_YEAR) * 100;

    // Information Ratio
    const annualizedActiveReturn = activeReturnMean * TRADING_DAYS_PER_YEAR * 100;
    const informationRatio = trackingError > 0 ? annualizedActiveReturn / trackingError : 0;

    return {
      alpha,
      beta,
      informationRatio,
      trackingError,
      correlation
    };
  }

  /**
   * Calculate drawdown data
   * ALIGNED with Analytics: uses NAV (equity) for consistency
   */
  private calculateDrawdownData(dailyReturns: DailyReturn[]): DrawdownData {
    let peak = dailyReturns[0]?.nav || 0;
    let maxDrawdownDepth = 0;
    let maxDrawdownDuration = 0;
    let currentDrawdownStart: number | null = null;
    const drawdownPeriods: DrawdownPeriod[] = [];

    for (let i = 0; i < dailyReturns.length; i++) {
      const currentDay = dailyReturns[i];
      if (!currentDay) continue;

      const current = currentDay.nav;

      if (current >= peak) {
        // New peak - end of drawdown period
        if (currentDrawdownStart !== null) {
          const duration = i - currentDrawdownStart;
          if (duration > maxDrawdownDuration) {
            maxDrawdownDuration = duration;
          }

          const startDay = dailyReturns[currentDrawdownStart];
          if (startDay) {
            const slicedNavs = dailyReturns.slice(currentDrawdownStart, i + 1).map(d => d.nav);
            drawdownPeriods.push({
              startDate: startDay.date,
              endDate: currentDay.date,
              depth: ((peak - Math.min(...slicedNavs)) / peak) * 100,
              duration,
              recovered: true
            });
          }

          currentDrawdownStart = null;
        }
        peak = current;
      } else {
        // In drawdown
        if (currentDrawdownStart === null) {
          currentDrawdownStart = i - 1;
        }

        const drawdown = ((peak - current) / peak) * 100;
        if (drawdown > maxDrawdownDepth) {
          maxDrawdownDepth = drawdown;
        }
      }
    }

    // Handle ongoing drawdown
    const lastReturn = dailyReturns[dailyReturns.length - 1];
    const currentDrawdown = lastReturn
      ? ((peak - lastReturn.nav) / peak) * 100
      : 0;

    if (currentDrawdownStart !== null) {
      const duration = dailyReturns.length - currentDrawdownStart;
      const ddStartDay = dailyReturns[currentDrawdownStart];
      if (ddStartDay) {
        drawdownPeriods.push({
          startDate: ddStartDay.date,
          endDate: lastReturn?.date || '',
          depth: currentDrawdown,
          duration,
          recovered: false
        });
      }
    }

    return {
      maxDrawdownDuration,
      currentDrawdown,
      drawdownPeriods: drawdownPeriods.slice(-5) // Keep last 5 drawdown periods
    };
  }

  /**
   * Fetch benchmark returns from benchmark service
   */
  private async fetchBenchmarkReturns(
    symbol: 'SPY' | 'BTC-USD',
    startDate: string,
    endDate: string
  ): Promise<Array<{ date: string; return: number }>> {
    try {
      const benchmarkServiceUrl = process.env.BENCHMARK_SERVICE_URL || 'http://localhost:8080';
      const backendSymbol = symbol === 'BTC-USD' ? 'BTCUSDT' : symbol;

      const url = `${benchmarkServiceUrl}/api/v1/benchmarks/${backendSymbol}/daily?startDate=${startDate}&endDate=${endDate}`;

      const response = await fetch(url);

      if (!response.ok) {
        logger.warn('Failed to fetch benchmark data', { symbol, status: response.status });
        return [];
      }

      const result = await response.json() as {
        success: boolean;
        data?: {
          data?: Array<{ date: string; adjustedClose: number }>;
        };
      };

      if (!result.success || !result.data?.data) {
        logger.warn('Invalid benchmark response format', { symbol });
        return [];
      }

      // Convert to daily returns
      const prices = result.data.data.sort((a, b) =>
        new Date(a.date).getTime() - new Date(b.date).getTime()
      );

      const benchmarkReturns: Array<{ date: string; return: number }> = [];

      for (let i = 1; i < prices.length; i++) {
        const currentPrice = prices[i];
        const previousPrice = prices[i - 1];

        if (!currentPrice || !previousPrice) continue;

        const current = currentPrice.adjustedClose;
        const previous = previousPrice.adjustedClose;

        if (previous > 0) {
          const dailyReturn = ((current - previous) / previous) * 100;
          benchmarkReturns.push({
            date: currentPrice.date,
            return: dailyReturn
          });
        }
      }

      return benchmarkReturns;

    } catch (error) {
      logger.error('Error fetching benchmark data', {
        symbol,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Merge benchmark returns with portfolio daily returns
   */
  private mergeBenchmarkReturns(
    dailyReturns: DailyReturn[],
    benchmarkReturns: Array<{ date: string; return: number }>
  ): Array<{ portfolioReturn: number; benchmarkReturn: number; date: string }> {
    const benchmarkMap = new Map(benchmarkReturns.map(b => [b.date, b.return]));

    return dailyReturns
      .filter(d => benchmarkMap.has(d.date))
      .map(d => ({
        portfolioReturn: d.netReturn / 100,
        benchmarkReturn: (benchmarkMap.get(d.date) || 0) / 100,
        date: d.date
      }));
  }

  /**
   * Calculate volatility (standard deviation)
   */
  private calculateVolatility(returns: number[]): number {
    if (returns.length <= 1) return 0;

    const mean = returns.reduce((sum, r) => sum + r, 0) / returns.length;
    const variance = returns.reduce((sum, r) => sum + Math.pow(r - mean, 2), 0) / (returns.length - 1);

    return Math.sqrt(variance);
  }

  /**
   * Calculate downside deviation (volatility of negative returns only)
   */
  private calculateDownsideDeviation(returns: number[]): number {
    const negativeReturns = returns.filter(r => r < 0);
    if (negativeReturns.length <= 1) return 0;

    const mean = 0; // MAR = 0 for downside deviation
    const variance = negativeReturns.reduce((sum, r) => sum + Math.pow(r - mean, 2), 0) / negativeReturns.length;

    return Math.sqrt(variance);
  }

  /**
   * Calculate maximum drawdown
   * ALIGNED with Analytics: uses NAV (equity) and returns POSITIVE value
   */
  private calculateMaxDrawdown(dailyReturns: DailyReturn[]): number {
    if (dailyReturns.length === 0) return 0;

    const firstDay = dailyReturns[0];
    if (!firstDay) return 0;

    // Use NAV (equity) for drawdown calculation, aligned with Analytics
    let peak = firstDay.nav;
    let maxDrawdown = 0;

    for (const day of dailyReturns) {
      if (day.nav > peak) {
        peak = day.nav;
      }

      const drawdown = ((peak - day.nav) / peak) * 100;
      if (drawdown > maxDrawdown) {
        maxDrawdown = drawdown;
      }
    }

    return maxDrawdown; // Return as POSITIVE value (aligned with Analytics)
  }
}
