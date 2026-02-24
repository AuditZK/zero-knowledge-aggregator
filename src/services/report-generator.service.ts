import { injectable, inject } from 'tsyringe';
import { randomBytes } from 'node:crypto';
import { SnapshotDataRepository } from '../core/repositories/snapshot-data-repository';
import { SignedReportRepository } from '../core/repositories/signed-report-repository';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { ReportSigningService } from './report-signing.service';
import { getLogger } from '../utils/secure-enclave-logger';
import { benchmarkServiceUrl } from '../config';
import {
  ReportRequest,
  SignedFinancialData,
  DisplayParameters,
  SignedReport,
  ReportMetrics,
  CoreMetrics,
  RiskMetrics,
  BenchmarkMetrics,
  DrawdownData,
  DrawdownPeriod,
  DailyReturn,
  MonthlyReturn,
  GenerateReportResult,
  ExchangeInfo,
} from '../types/report.types';

const logger = getLogger('ReportGenerator');

// Enclave version for report tracking
const ENCLAVE_VERSION = process.env.ENCLAVE_VERSION || '3.0.0';

// Constants
const TRADING_DAYS_PER_YEAR = 365;
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
    @inject(SignedReportRepository) private readonly reportRepo: SignedReportRepository,
    @inject(ExchangeConnectionRepository) private readonly connectionRepo: ExchangeConnectionRepository,
    @inject(ReportSigningService) private readonly signingService: ReportSigningService
  ) {}

  /**
   * Generate a signed track record report
   *
   * DEDUPLICATION: Returns cached report if same period was already generated.
   * The cached FINANCIAL DATA is returned, but DISPLAY PARAMETERS are applied fresh.
   *
   * ARCHITECTURE:
   * - SignedFinancialData: Cached and signed (metrics, returns, period)
   * - DisplayParameters: Applied per request (reportName, manager, firm)
   * - Signature proves the NUMBERS, not arbitrary text labels
   */
  async generateSignedReport(request: ReportRequest): Promise<GenerateReportResult> {
    const displayParams = this.extractDisplayParams(request);

    logger.info('Generating signed report', {
      userUid: request.userUid,
      startDate: request.startDate,
      endDate: request.endDate,
      benchmark: request.benchmark,
      displayParams: { reportName: displayParams.reportName }
    });

    try {
      // Check cache first
      const cachedResult = await this.checkCachedReport(request, displayParams);
      if (cachedResult) return cachedResult;

      // Generate new report
      return await this.generateNewReport(request, displayParams);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error('Failed to generate signed report', { error: errorMessage });
      return {
        success: false,
        error: errorMessage
      };
    }
  }

  private extractDisplayParams(request: ReportRequest): DisplayParameters {
    return request.displayParams || { reportName: 'Track Record Report' };
  }

  private async checkCachedReport(
    request: ReportRequest,
    displayParams: DisplayParameters
  ): Promise<GenerateReportResult | null> {
    const startDate = request.startDate ? new Date(request.startDate) : undefined;
    const endDate = request.endDate ? new Date(request.endDate) : undefined;

    if (!startDate || !endDate) return null;

    const existingReport = await this.reportRepo.findByPeriod(
      request.userUid,
      startDate,
      endDate,
      request.benchmark || null
    );

    if (!existingReport) return null;

    logger.info('Found cached financial data, applying new display parameters', {
      reportId: existingReport.reportId,
      originalCreatedAt: existingReport.createdAt.toISOString(),
      newDisplayParams: { reportName: displayParams.reportName }
    });

    const cachedReport = existingReport.reportData as unknown as SignedReport;
    return {
      success: true,
      signedReport: { ...cachedReport, displayParams },
      cached: true
    };
  }

  private async generateNewReport(
    request: ReportRequest,
    displayParams: DisplayParameters
  ): Promise<GenerateReportResult> {
    // 1. Fetch and validate snapshots (exclude connections marked excludeFromReport)
    const allSnapshots = await this.snapshotRepo.getSnapshotData(
      request.userUid,
      request.startDate ? new Date(request.startDate) : undefined,
      request.endDate ? new Date(request.endDate) : undefined
    );
    const excludedKeys = await this.connectionRepo.getExcludedKeysForUser(request.userUid);
    const snapshots = excludedKeys.size > 0
      ? allSnapshots.filter(s => !excludedKeys.has(s.label ? `${s.exchange}/${s.label}` : s.exchange))
      : allSnapshots;

    if (snapshots.length === 0) {
      return { success: false, error: 'No snapshot data found for the specified period' };
    }

    // 2. Convert to daily returns
    const dailyReturns = this.convertSnapshotsToDailyReturns(snapshots);
    if (dailyReturns.length < 2) {
      return { success: false, error: 'Insufficient data for report generation (need at least 2 days)' };
    }

    // 3. Calculate all metrics
    const monthlyReturns = this.aggregateToMonthlyReturns(dailyReturns);
    const metrics = this.buildMetrics(request, dailyReturns);

    // 4. Process benchmark if requested
    await this.processBenchmark(request, dailyReturns, metrics);

    // 5. Build and sign the financial data
    const exchangeDetails = await this.buildExchangeDetails(request.userUid, snapshots);
    const financialData = this.buildFinancialData(request, snapshots, dailyReturns, monthlyReturns, metrics, exchangeDetails);
    const signedReport = this.signingService.signFinancialData(financialData, displayParams);

    this.logReportGeneration(financialData, displayParams);

    // 6. Save for deduplication (non-blocking)
    await this.saveReportForDeduplication(request, financialData, signedReport);

    return { success: true, signedReport };
  }

  private buildMetrics(request: ReportRequest, dailyReturns: DailyReturn[]): ReportMetrics {
    const metrics: ReportMetrics = { ...this.calculateCoreMetrics(dailyReturns) };

    if (request.includeRiskMetrics) {
      metrics.riskMetrics = this.calculateRiskMetrics(dailyReturns);
    }
    if (request.includeDrawdown) {
      metrics.drawdownData = this.calculateDrawdownData(dailyReturns);
    }

    return metrics;
  }

  private async processBenchmark(
    request: ReportRequest,
    dailyReturns: DailyReturn[],
    metrics: ReportMetrics
  ): Promise<void> {
    if (!request.benchmark) return;

    const firstDay = dailyReturns[0];
    const lastDay = dailyReturns.at(-1);
    if (!firstDay || !lastDay) return;

    const benchmarkReturns = await this.fetchBenchmarkReturns(request.benchmark, firstDay.date, lastDay.date);
    if (benchmarkReturns.length === 0) return;

    const benchmarkMap = new Map(benchmarkReturns.map(b => [b.date, b.return]));
    const mergedReturns = this.mergeBenchmarkReturns(dailyReturns, benchmarkReturns);
    metrics.benchmarkMetrics = this.calculateBenchmarkMetrics(mergedReturns);

    dailyReturns.forEach((dr) => {
      const benchReturn = benchmarkMap.get(dr.date);
      if (benchReturn !== undefined) {
        dr.benchmarkReturn = benchReturn;
        dr.outperformance = dr.netReturn - benchReturn;
      }
    });
  }

  private buildFinancialData(
    request: ReportRequest,
    snapshots: Array<{ exchange?: string }>,
    dailyReturns: DailyReturn[],
    monthlyReturns: MonthlyReturn[],
    metrics: ReportMetrics,
    exchangeDetails?: ExchangeInfo[]
  ): SignedFinancialData {
    const firstDay = dailyReturns[0]!;
    const lastDay = dailyReturns.at(-1)!;
    const exchanges = Array.from(new Set(snapshots.map(s => s.exchange || 'unknown'))).sort((a, b) => a.localeCompare(b));

    return {
      reportId: this.generateReportId(),
      userUid: request.userUid,
      generatedAt: new Date(),
      periodStart: new Date(firstDay.date),
      periodEnd: new Date(lastDay.date),
      baseCurrency: request.baseCurrency || 'USD',
      benchmark: request.benchmark,
      dataPoints: dailyReturns.length,
      exchanges,
      exchangeDetails,
      metrics,
      dailyReturns,
      monthlyReturns
    };
  }

  private async buildExchangeDetails(
    userUid: string,
    snapshots: Array<{ exchange?: string }>
  ): Promise<ExchangeInfo[]> {
    const exchangeNames = Array.from(new Set(snapshots.map(s => s.exchange || 'unknown')));
    const [kycMap, paperMap] = await Promise.all([
      this.connectionRepo.getKycLevelsForUser(userUid),
      this.connectionRepo.getPaperStatusForUser(userUid),
    ]);

    return [...exchangeNames].sort((a, b) => a.localeCompare(b)).map(name => ({
      name,
      kycLevel: kycMap.get(name),
      isPaper: paperMap.get(name),
    }));
  }

  private logReportGeneration(financialData: SignedFinancialData, displayParams: DisplayParameters): void {
    logger.info('Signed report generated successfully', {
      reportId: financialData.reportId,
      dataPoints: financialData.dataPoints,
      periodStart: financialData.periodStart.toISOString(),
      periodEnd: financialData.periodEnd.toISOString(),
      exchanges: financialData.exchanges,
      displayParams: { reportName: displayParams.reportName }
    });
  }

  private async saveReportForDeduplication(
    request: ReportRequest,
    financialData: SignedFinancialData,
    signedReport: SignedReport
  ): Promise<void> {
    try {
      await this.reportRepo.save({
        reportId: financialData.reportId,
        userUid: request.userUid,
        startDate: financialData.periodStart,
        endDate: financialData.periodEnd,
        benchmark: request.benchmark || null,
        reportData: signedReport as unknown as Record<string, unknown>,
        signature: signedReport.signature || '',
        reportHash: signedReport.reportHash || '',
        enclaveVersion: ENCLAVE_VERSION
      });
      logger.info('Report saved to database for deduplication', { reportId: financialData.reportId });
    } catch (saveError) {
      logger.warn('Failed to save report for deduplication (report still valid)', {
        error: saveError instanceof Error ? saveError.message : 'Unknown error'
      });
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
    label?: string;
  }>): DailyReturn[] {
    const byDateAndExchange = this.groupSnapshotsByDateAndExchange(snapshots);
    const sortedDates = Array.from(byDateAndExchange.keys()).sort((a, b) => a.localeCompare(b));

    const state = this.initDailyReturnState(sortedDates);
    const dailyReturns: DailyReturn[] = [];

    for (const dateKey of sortedDates) {
      const exchangeMap = byDateAndExchange.get(dateKey)!;
      const dayData = this.aggregateDailyEquityAndCashflows(
        exchangeMap, state, dateKey
      );

      const result = this.calculateDailyReturnForDate(dateKey, dayData, state);
      dailyReturns.push(result);
    }

    return dailyReturns;
  }

  private groupSnapshotsByDateAndExchange(snapshots: Array<{
    timestamp: string;
    totalEquity: number;
    deposits: number;
    withdrawals: number;
    exchange?: string;
    label?: string;
  }>): Map<string, Map<string, typeof snapshots>> {
    const byDateAndExchange = new Map<string, Map<string, typeof snapshots>>();

    for (const snapshot of snapshots) {
      const dateKey = new Date(snapshot.timestamp).toISOString().split('T')[0];
      if (!dateKey) continue;

      // Group by exchange+label to handle multi-account exchanges (e.g. Hyperliquid sub-accounts)
      const exchange = snapshot.label
        ? `${snapshot.exchange || 'unknown'}|${snapshot.label}`
        : (snapshot.exchange || 'unknown');

      if (!byDateAndExchange.has(dateKey)) {
        byDateAndExchange.set(dateKey, new Map());
      }
      const exchangeMap = byDateAndExchange.get(dateKey)!;

      if (!exchangeMap.has(exchange)) {
        exchangeMap.set(exchange, []);
      }
      exchangeMap.get(exchange)!.push(snapshot);
    }

    return byDateAndExchange;
  }

  private initDailyReturnState(_sortedDates: string[]) {
    return {
      seenExchanges: new Set<string>(),
      everSeenExchanges: new Set<string>(),
      lastKnownEquity: new Map<string, number>(),
      previousCloseEquity: null as number | null,
      cumulativeReturn: 1,
      firstDateKey: null as string | null,
    };
  }

  private aggregateDailyEquityAndCashflows(
    exchangeMap: Map<string, Array<{ timestamp: string; totalEquity: number; deposits: number; withdrawals: number }>>,
    state: { seenExchanges: Set<string>; everSeenExchanges: Set<string>; lastKnownEquity: Map<string, number>; firstDateKey: string | null },
    dateKey: string,
  ): { totalEquity: number; netDeposits: number } {
    if (state.firstDateKey === null) {
      state.firstDateKey = dateKey;
    }

    let totalEquity = 0;
    let totalDeposits = 0;
    let totalWithdrawals = 0;
    let virtualDeposit = 0;

    for (const [exchange, daySnapshots] of exchangeMap.entries()) {
      const sorted = [...daySnapshots].sort((a, b) =>
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );
      const closeSnap = sorted.at(-1)!;

      totalEquity += closeSnap.totalEquity;
      totalDeposits += closeSnap.deposits;
      totalWithdrawals += closeSnap.withdrawals;
      state.lastKnownEquity.set(exchange, closeSnap.totalEquity);

      if (!state.seenExchanges.has(exchange)) {
        state.seenExchanges.add(exchange);
        // Virtual deposit: exchange reappeared after disappearing (was withdrawn then came back)
        if (dateKey !== state.firstDateKey && state.everSeenExchanges.has(exchange) && closeSnap.deposits === 0) {
          virtualDeposit += closeSnap.totalEquity;
        }
      }
      state.everSeenExchanges.add(exchange);
    }

    // Virtual withdrawal: missing exchange = immediate withdrawal of last known equity
    let virtualWithdrawal = 0;
    const disappearedExchanges: string[] = [];
    for (const prevExchange of state.seenExchanges) {
      if (!exchangeMap.has(prevExchange)) {
        virtualWithdrawal += state.lastKnownEquity.get(prevExchange) || 0;
        disappearedExchanges.push(prevExchange);
      }
    }
    for (const ex of disappearedExchanges) {
      state.seenExchanges.delete(ex);
      state.lastKnownEquity.delete(ex);
    }

    return {
      totalEquity,
      netDeposits: totalDeposits - totalWithdrawals + virtualDeposit - virtualWithdrawal
    };
  }

  private calculateDailyReturnForDate(
    dateKey: string,
    dayData: { totalEquity: number; netDeposits: number },
    state: { previousCloseEquity: number | null; cumulativeReturn: number }
  ): DailyReturn {
    let dailyReturnPct = 0;

    if (state.previousCloseEquity !== null && state.previousCloseEquity > 0) {
      const adjustedReturn = dayData.totalEquity - state.previousCloseEquity - dayData.netDeposits;
      dailyReturnPct = (adjustedReturn / state.previousCloseEquity) * 100;
      state.cumulativeReturn *= (1 + dailyReturnPct / 100);
    }

    state.previousCloseEquity = dayData.totalEquity;

    return {
      date: dateKey,
      netReturn: dailyReturnPct,
      benchmarkReturn: 0,
      outperformance: dailyReturnPct,
      cumulativeReturn: state.cumulativeReturn,
      nav: dayData.totalEquity
    };
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

      const sortedData = [...dailyData].sort((a, b) => a.date.localeCompare(b.date));
      const firstDay = sortedData[0];
      const lastDay = sortedData.at(-1);

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
    const lastDay = dailyReturns.at(-1);
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
    const state = this.initDrawdownCalcState(dailyReturns);

    for (let i = 0; i < dailyReturns.length; i++) {
      const currentDay = dailyReturns[i];
      if (!currentDay) continue;

      this.processDrawdownDay(dailyReturns, i, currentDay, state);
    }

    return this.finalizeDrawdownData(dailyReturns, state);
  }

  private initDrawdownCalcState(dailyReturns: DailyReturn[]) {
    return {
      peak: dailyReturns[0]?.nav || 0,
      maxDrawdownDepth: 0,
      maxDrawdownDuration: 0,
      currentDrawdownStart: null as number | null,
      drawdownPeriods: [] as DrawdownPeriod[]
    };
  }

  private processDrawdownDay(
    dailyReturns: DailyReturn[],
    index: number,
    currentDay: DailyReturn,
    state: ReturnType<typeof this.initDrawdownCalcState>
  ): void {
    const current = currentDay.nav;

    if (current >= state.peak) {
      this.handleNewPeak(dailyReturns, index, currentDay, state);
    } else {
      this.handleDrawdown(index, current, state);
    }
  }

  private handleNewPeak(
    dailyReturns: DailyReturn[],
    index: number,
    currentDay: DailyReturn,
    state: ReturnType<typeof this.initDrawdownCalcState>
  ): void {
    if (state.currentDrawdownStart !== null) {
      const duration = index - state.currentDrawdownStart;
      state.maxDrawdownDuration = Math.max(state.maxDrawdownDuration, duration);

      const startDay = dailyReturns[state.currentDrawdownStart];
      if (startDay) {
        const slicedNavs = dailyReturns.slice(state.currentDrawdownStart, index + 1).map(d => d.nav);
        state.drawdownPeriods.push({
          startDate: startDay.date,
          endDate: currentDay.date,
          depth: ((state.peak - Math.min(...slicedNavs)) / state.peak) * 100,
          duration,
          recovered: true
        });
      }

      state.currentDrawdownStart = null;
    }
    state.peak = currentDay.nav;
  }

  private handleDrawdown(
    index: number,
    current: number,
    state: ReturnType<typeof this.initDrawdownCalcState>
  ): void {
    state.currentDrawdownStart ??= index - 1;

    const drawdown = ((state.peak - current) / state.peak) * 100;
    state.maxDrawdownDepth = Math.max(state.maxDrawdownDepth, drawdown);
  }

  private finalizeDrawdownData(
    dailyReturns: DailyReturn[],
    state: ReturnType<typeof this.initDrawdownCalcState>
  ): DrawdownData {
    const lastReturn = dailyReturns.at(-1);
    const currentDrawdown = lastReturn
      ? ((state.peak - lastReturn.nav) / state.peak) * 100
      : 0;

    if (state.currentDrawdownStart !== null) {
      const duration = dailyReturns.length - state.currentDrawdownStart;
      const ddStartDay = dailyReturns[state.currentDrawdownStart];
      if (ddStartDay) {
        state.drawdownPeriods.push({
          startDate: ddStartDay.date,
          endDate: lastReturn?.date || '',
          depth: currentDrawdown,
          duration,
          recovered: false
        });
      }
    }

    return {
      maxDrawdownDuration: state.maxDrawdownDuration,
      currentDrawdown,
      drawdownPeriods: state.drawdownPeriods.slice(-5)
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

      // Convert to daily returns (sort without mutating original)
      const prices = [...result.data.data].sort((a, b) =>
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
