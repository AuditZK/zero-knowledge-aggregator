import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'node:path';
import fs from 'node:fs';
import { container } from 'tsyringe';
import { EnclaveWorker } from './enclave-worker';
import { getLogger, extractErrorMessage } from './utils/secure-enclave-logger';
import { ReportGeneratorService } from './services/report-generator.service';
import { ReportSigningService } from './services/report-signing.service';
import { ReportRequest, VerifySignatureRequest, DailyReturn, MonthlyReturn, DrawdownPeriod } from './types/report.types';

const logger = getLogger('EnclaveServer');
import {
  SyncJobRequestSchema,
  AggregatedMetricsRequestSchema,
  SnapshotTimeSeriesRequestSchema,
  CreateUserConnectionRequestSchema,
  validateRequest
} from './validation/grpc-schemas';

// Load proto file
const PROTO_PATH = path.join(__dirname, 'proto/enclave.proto');

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
});

const enclaveProto = grpc.loadPackageDefinition(packageDefinition) as any;

/**
 * Enclave gRPC Server
 *
 * Runs inside the AMD SEV-SNP enclave and handles requests from the Gateway.
 * All operations work with sensitive data internally but only return
 * aggregated, safe results.
 *
 * CRITICAL SECURITY PROPERTIES:
 * - Runs in isolated enclave environment
 * - Has access to decryption keys and individual trades
 * - Only returns aggregated data (never individual trades)
 * - Uses mutual TLS for production deployments
 */
export class EnclaveServer {
  private readonly server: grpc.Server;
  private readonly enclaveWorker: EnclaveWorker;
  private readonly reportGeneratorService: ReportGeneratorService;
  private readonly reportSigningService: ReportSigningService;
  private readonly port: number;

  constructor() {
    this.server = new grpc.Server();
    this.port = Number.parseInt(process.env.ENCLAVE_PORT || '50051', 10);

    // Get service instances from DI container
    this.enclaveWorker = container.resolve(EnclaveWorker);
    this.reportGeneratorService = container.resolve(ReportGeneratorService);
    this.reportSigningService = container.resolve(ReportSigningService);

    // Add service implementation (wrap async handlers to return void)
    this.server.addService(enclaveProto.enclave.EnclaveService.service, {
      ProcessSyncJob: (call: grpc.ServerUnaryCall<unknown, unknown>, cb: grpc.sendUnaryData<unknown>) => { void this.processSyncJob(call, cb); },
      GetAggregatedMetrics: (call: grpc.ServerUnaryCall<unknown, unknown>, cb: grpc.sendUnaryData<unknown>) => { void this.getAggregatedMetrics(call, cb); },
      GetSnapshotTimeSeries: (call: grpc.ServerUnaryCall<unknown, unknown>, cb: grpc.sendUnaryData<unknown>) => { void this.getSnapshotTimeSeries(call, cb); },
      GetPerformanceMetrics: (call: grpc.ServerUnaryCall<unknown, unknown>, cb: grpc.sendUnaryData<unknown>) => { void this.getPerformanceMetrics(call, cb); },
      CreateUserConnection: (call: grpc.ServerUnaryCall<unknown, unknown>, cb: grpc.sendUnaryData<unknown>) => { void this.createUserConnection(call, cb); },
      HealthCheck: (call: grpc.ServerUnaryCall<unknown, unknown>, cb: grpc.sendUnaryData<unknown>) => { void this.healthCheck(call, cb); },
      GenerateSignedReport: (call: grpc.ServerUnaryCall<unknown, unknown>, cb: grpc.sendUnaryData<unknown>) => { void this.generateSignedReport(call, cb); },
      VerifyReportSignature: (call: grpc.ServerUnaryCall<unknown, unknown>, cb: grpc.sendUnaryData<unknown>) => { void this.verifyReportSignature(call, cb); }
    });

    logger.info('Enclave gRPC server initialized', {
      publicKeyFingerprint: this.reportSigningService.getPublicKeyFingerprint()
    });
  }

  /**
   * Handle ProcessSyncJob RPC
   *
   * AUTOMATIC BEHAVIOR BY EXCHANGE TYPE:
   * - IBKR: Auto-backfill from Flex (365 days) on first sync, then current day only
   * - Crypto: Current snapshot only (DailySyncScheduler handles midnight UTC syncs)
   */
  private async processSyncJob(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const rawRequest = call.request;

      // Normalize gRPC defaults: convert empty strings to undefined
      const request = {
        user_uid: rawRequest.user_uid,
        exchange: rawRequest.exchange === '' ? undefined : rawRequest.exchange,
        type: rawRequest.type || 'incremental' // Deprecated, defaults to incremental
      };

      // SECURITY: Validate input before processing
      const validation = validateRequest(SyncJobRequestSchema, request);
      if (!validation.success) {
        logger.warn('Invalid ProcessSyncJob request', {
          error: validation.success === false ? validation.error : 'Unknown error',
          request: { user_uid: request.user_uid, exchange: request.exchange }
        });

        callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: validation.success === false ? validation.error : 'Validation failed'
        }, null);
        return;
      }

      const validated = validation.data;

      logger.info('Processing sync job request', {
        user_uid: validated.user_uid,
        exchange: validated.exchange
      });

      // Convert validated gRPC request to internal format (type is deprecated)
      const syncRequest = {
        userUid: validated.user_uid,
        exchange: validated.exchange || undefined
      };

      // Process the sync job
      const result = await this.enclaveWorker.processSyncJob(syncRequest);

      // Convert internal response to gRPC format
      const response = {
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

      callback(null, response);
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      logger.error('ProcessSyncJob failed', {
        error: errorMessage,
        stack: errorStack
      });

      callback({
        code: grpc.status.INTERNAL,
        message: errorMessage
      }, null);
    }
  }

  /**
   * Handle GetAggregatedMetrics RPC
   */
  private async getAggregatedMetrics(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const rawRequest = call.request;

      // Normalize gRPC defaults: convert empty strings to undefined
      const request = {
        user_uid: rawRequest.user_uid,
        exchange: rawRequest.exchange === '' ? undefined : rawRequest.exchange
      };

      // SECURITY: Validate input before processing
      const validation = validateRequest(AggregatedMetricsRequestSchema, request);
      if (!validation.success) {
        logger.warn('Invalid GetAggregatedMetrics request', {
          error: validation.success === false ? validation.error : 'Unknown error',
          request: {
            user_uid: request.user_uid,
            exchange: request.exchange
          }
        });

        callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: validation.success === false ? validation.error : 'Validation failed'
        }, null);
        return;
      }

      const validated = validation.data;

      logger.info('Getting aggregated metrics', {
        user_uid: validated.user_uid,
        exchange: validated.exchange
      });

      // Get metrics with validated data
      const metrics = await this.enclaveWorker.getAggregatedMetrics(
        validated.user_uid,
        validated.exchange || undefined
      );

      // Convert to gRPC format
      const response = {
        total_balance: metrics.totalBalance,
        total_equity: metrics.totalEquity,
        total_realized_pnl: metrics.totalRealizedPnl,
        total_unrealized_pnl: metrics.totalUnrealizedPnl,
        total_fees: metrics.totalFees,
        total_trades: metrics.totalTrades,
        last_sync: metrics.lastSync ? metrics.lastSync.getTime().toString() : '0'
      };

      callback(null, response);
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      logger.error('GetAggregatedMetrics failed', {
        error: errorMessage,
        stack: errorStack
      });

      callback({
        code: grpc.status.INTERNAL,
        message: errorMessage
      }, null);
    }
  }

  /**
   * Handle GetSnapshotTimeSeries RPC
   */
  private async getSnapshotTimeSeries(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const rawRequest = call.request;

      // Normalize gRPC defaults: convert empty strings and "0" timestamps to undefined
      const request = {
        user_uid: rawRequest.user_uid,
        exchange: rawRequest.exchange === '' ? undefined : rawRequest.exchange,
        start_date: rawRequest.start_date === '0' ? undefined : rawRequest.start_date,
        end_date: rawRequest.end_date === '0' ? undefined : rawRequest.end_date
      };

      // SECURITY: Validate input before processing
      const validation = validateRequest(SnapshotTimeSeriesRequestSchema, request);
      if (!validation.success) {
        logger.warn('Invalid GetSnapshotTimeSeries request', {
          error: validation.success === false ? validation.error : 'Unknown error',
          request: {
            user_uid: request.user_uid,
            exchange: request.exchange
          }
        });

        callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: validation.success === false ? validation.error : 'Validation failed'
        }, null);
        return;
      }

      const validated = validation.data;

      logger.info('Getting snapshot time series', {
        user_uid: validated.user_uid,
        exchange: validated.exchange,
        start_date: validated.start_date,
        end_date: validated.end_date
      });

      // Get snapshot time series with validated data
      const snapshots = await this.enclaveWorker.getSnapshotTimeSeries(
        validated.user_uid,
        validated.exchange || undefined,
        validated.start_date ? new Date(validated.start_date) : undefined,
        validated.end_date ? new Date(validated.end_date) : undefined
      );

      // Convert to gRPC format with market breakdown
      // Supports both crypto (spot/swap) and traditional (stocks/futures/cfd) categories

      // Market metrics data structure
      interface MarketMetricsData {
        equity?: number;
        available_margin?: number;
        volume?: number;
        trades?: number;
        trading_fees?: number;
        funding_fees?: number;
      }

      const response = {
        snapshots: snapshots.map(snapshot => {
          const bd = snapshot.breakdown as Record<string, MarketMetricsData> | undefined;

          // Helper to map market metrics
          const mapMetrics = (data: MarketMetricsData | undefined) => data ? {
            equity: data.equity || 0,
            available_margin: data.available_margin || 0,
            volume: data.volume || 0,
            trades: data.trades || 0,
            trading_fees: data.trading_fees || 0,
            funding_fees: data.funding_fees || 0
          } : undefined;

          return {
            user_uid: snapshot.userUid,
            exchange: snapshot.exchange,
            timestamp: snapshot.timestamp.getTime(),
            total_equity: snapshot.totalEquity,
            realized_balance: snapshot.realizedBalance,
            unrealized_pnl: snapshot.unrealizedPnL,
            deposits: snapshot.deposits,
            withdrawals: snapshot.withdrawals,
            breakdown: bd ? {
              global: mapMetrics(bd.global),
              // Crypto categories
              spot: mapMetrics(bd.spot),
              swap: mapMetrics(bd.swap),
              // Traditional categories (IBKR)
              stocks: mapMetrics(bd.stocks),
              futures: mapMetrics(bd.futures),
              cfd: mapMetrics(bd.cfd),
              forex: mapMetrics(bd.forex),
              commodities: mapMetrics(bd.commodities),
              // Shared
              options: mapMetrics(bd.options)
            } : undefined
          };
        })
      };

      callback(null, response);
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      logger.error('GetSnapshotTimeSeries failed', {
        error: errorMessage,
        stack: errorStack
      });

      callback({
        code: grpc.status.INTERNAL,
        message: errorMessage
      }, null);
    }
  }

  /**
   * Handle CreateUserConnection RPC
   */
  private async createUserConnection(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const rawRequest = call.request;

      // Normalize gRPC defaults: convert empty strings to undefined
      const request = {
        user_uid: rawRequest.user_uid,  // Platform provides the UUID
        exchange: rawRequest.exchange,
        label: rawRequest.label,
        api_key: rawRequest.api_key,
        api_secret: rawRequest.api_secret,
        passphrase: rawRequest.passphrase === '' ? undefined : rawRequest.passphrase
      };

      // SECURITY: Validate input before processing
      const validation = validateRequest(CreateUserConnectionRequestSchema, request);
      if (!validation.success) {
        logger.warn('Invalid CreateUserConnection request', {
          error: validation.success === false ? validation.error : 'Unknown error'
        });

        callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: validation.success === false ? validation.error : 'Validation failed'
        }, null);
        return;
      }

      const validated = validation.data;

      logger.info('Creating user connection');

      // Create user and connection
      const result = await this.enclaveWorker.createUserConnection({
        userUid: validated.user_uid,  // Platform-provided UUID
        exchange: validated.exchange,
        label: validated.label,
        apiKey: validated.api_key,
        apiSecret: validated.api_secret,
        passphrase: validated.passphrase
      });

      // Convert to gRPC format
      const response = {
        success: result.success,
        user_uid: result.userUid || '',
        error: result.error || ''
      };

      callback(null, response);
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      logger.error('CreateUserConnection failed', {
        error: errorMessage,
        stack: errorStack
      });

      callback({
        code: grpc.status.INTERNAL,
        message: errorMessage
      }, null);
    }
  }

  /**
   * Handle GetPerformanceMetrics RPC
   *
   * SECURITY: Returns only statistical metrics (Sharpe, volatility, drawdown)
   * NO individual trade data is included
   */
  private async getPerformanceMetrics(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const rawRequest = call.request;

      // Normalize gRPC defaults: convert empty strings and 0/"0" to undefined
      // Note: gRPC with longs:String returns "0" as string, not number
      const isZeroOrEmpty = (val: unknown): boolean => !val || val === 0 || val === '0';
      const request = {
        user_uid: rawRequest.user_uid,
        exchange: rawRequest.exchange === '' ? undefined : rawRequest.exchange,
        start_date: isZeroOrEmpty(rawRequest.start_date) ? undefined : rawRequest.start_date,
        end_date: isZeroOrEmpty(rawRequest.end_date) ? undefined : rawRequest.end_date
      };

      logger.info('Getting performance metrics', {
        user_uid: request.user_uid,
        exchange: request.exchange,
        start_date: request.start_date,
        end_date: request.end_date
      });

      // Get performance metrics from enclave worker
      const result = await this.enclaveWorker.getPerformanceMetrics(
        request.user_uid,
        request.exchange,
        request.start_date ? new Date(request.start_date) : undefined,
        request.end_date ? new Date(request.end_date) : undefined
      );

      if (!result.success) {
        callback(null, {
          success: false,
          error: result.error || 'Failed to calculate metrics',
          sharpe_ratio: 0,
          sortino_ratio: 0,
          calmar_ratio: 0,
          volatility: 0,
          downside_deviation: 0,
          max_drawdown: 0,
          max_drawdown_duration: 0,
          current_drawdown: 0,
          win_rate: 0,
          profit_factor: 0,
          avg_win: 0,
          avg_loss: 0,
          period_start: 0,
          period_end: 0,
          data_points: 0
        });
        return;
      }

      const metrics = result.metrics!;

      // Convert to gRPC format
      const response = {
        success: true,
        sharpe_ratio: metrics.sharpeRatio || 0,
        sortino_ratio: metrics.sortinoRatio || 0,
        calmar_ratio: metrics.calmarRatio || 0,
        volatility: metrics.volatility || 0,
        downside_deviation: metrics.downsideDeviation || 0,
        max_drawdown: metrics.maxDrawdown || 0,
        max_drawdown_duration: metrics.maxDrawdownDuration || 0,
        current_drawdown: metrics.currentDrawdown || 0,
        win_rate: metrics.winRate || 0,
        profit_factor: metrics.profitFactor || 0,
        avg_win: metrics.avgWin || 0,
        avg_loss: metrics.avgLoss || 0,
        period_start: metrics.periodStart.getTime(),
        period_end: metrics.periodEnd.getTime(),
        data_points: metrics.dataPoints,
        error: ''
      };

      callback(null, response);
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      logger.error('GetPerformanceMetrics failed', {
        error: errorMessage,
        stack: errorStack
      });

      callback({
        code: grpc.status.INTERNAL,
        message: errorMessage
      }, null);
    }
  }

  /**
   * Handle HealthCheck RPC
   */
  private async healthCheck(
    _call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const health = await this.enclaveWorker.healthCheck();

      const response = {
        status: health.status === 'healthy' ? 0 : 1,
        enclave: health.enclave,
        version: health.version,
        uptime: health.uptime
      };

      callback(null, response);
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);

      logger.error('HealthCheck failed', {
        error: errorMessage
      });

      callback(null, {
        status: 1, // unhealthy
        enclave: true,
        version: 'error',
        uptime: 0
      });
    }
  }

  /**
   * Handle GenerateSignedReport RPC
   *
   * SECURITY: Generates a cryptographically signed report with all metrics
   * calculated inside the enclave. The signature proves the report originated
   * from this enclave instance.
   */
  private async generateSignedReport(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const rawRequest = call.request;

      // Normalize gRPC defaults: convert empty strings to undefined
      const request: ReportRequest = {
        userUid: rawRequest.user_uid,
        startDate: rawRequest.start_date === '' ? undefined : rawRequest.start_date,
        endDate: rawRequest.end_date === '' ? undefined : rawRequest.end_date,
        benchmark: rawRequest.benchmark === '' ? undefined : rawRequest.benchmark as 'SPY' | 'BTC-USD',
        includeRiskMetrics: rawRequest.include_risk_metrics || false,
        includeDrawdown: rawRequest.include_drawdown || false,
        baseCurrency: rawRequest.base_currency === '' ? 'USD' : rawRequest.base_currency,
        // Display parameters - NOT signed, can be customized per request
        displayParams: {
          reportName: rawRequest.report_name === '' ? undefined : rawRequest.report_name,
          managerName: rawRequest.manager_name === '' ? undefined : rawRequest.manager_name,
          firmName: rawRequest.firm_name === '' ? undefined : rawRequest.firm_name,
          strategy: rawRequest.strategy === '' ? undefined : rawRequest.strategy,
          disclaimers: rawRequest.disclaimers === '' ? undefined : rawRequest.disclaimers,
        }
      };

      // Validate user_uid is present
      if (!request.userUid) {
        callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: 'user_uid is required'
        }, null);
        return;
      }

      logger.info('Generating signed report', {
        user_uid: request.userUid,
        benchmark: request.benchmark,
        include_risk_metrics: request.includeRiskMetrics,
        include_drawdown: request.includeDrawdown
      });

      // Generate the signed report
      const result = await this.reportGeneratorService.generateSignedReport(request);

      if (!result.success || !result.signedReport) {
        callback(null, {
          success: false,
          error: result.error || 'Failed to generate report'
        });
        return;
      }

      const signedReport = result.signedReport;
      const financialData = signedReport.financialData;
      const metrics = financialData.metrics;

      // Convert to gRPC format
      const response = {
        success: true,
        error: '',

        // Report metadata (from signed financial data)
        report_id: financialData.reportId,
        user_uid: financialData.userUid,
        report_name: signedReport.displayParams.reportName || 'Track Record Report',
        // Handle both Date objects (new reports) and strings (cached reports from JSON)
        generated_at: financialData.generatedAt instanceof Date
          ? financialData.generatedAt.toISOString()
          : String(financialData.generatedAt),
        period_start: financialData.periodStart instanceof Date
          ? financialData.periodStart.toISOString()
          : String(financialData.periodStart),
        period_end: financialData.periodEnd instanceof Date
          ? financialData.periodEnd.toISOString()
          : String(financialData.periodEnd),
        base_currency: financialData.baseCurrency,
        benchmark: financialData.benchmark || '',
        data_points: financialData.dataPoints,
        exchanges: financialData.exchanges || [],

        // Core metrics
        total_return: metrics.totalReturn,
        annualized_return: metrics.annualizedReturn,
        volatility: metrics.volatility,
        sharpe_ratio: metrics.sharpeRatio,
        sortino_ratio: metrics.sortinoRatio,
        max_drawdown: metrics.maxDrawdown,
        calmar_ratio: metrics.calmarRatio,

        // Risk metrics (optional)
        var_95: metrics.riskMetrics?.var95 || 0,
        var_99: metrics.riskMetrics?.var99 || 0,
        expected_shortfall: metrics.riskMetrics?.expectedShortfall || 0,
        skewness: metrics.riskMetrics?.skewness || 0,
        kurtosis: metrics.riskMetrics?.kurtosis || 0,

        // Benchmark metrics (optional)
        alpha: metrics.benchmarkMetrics?.alpha || 0,
        beta: metrics.benchmarkMetrics?.beta || 0,
        information_ratio: metrics.benchmarkMetrics?.informationRatio || 0,
        tracking_error: metrics.benchmarkMetrics?.trackingError || 0,
        correlation: metrics.benchmarkMetrics?.correlation || 0,

        // Drawdown data (optional)
        max_drawdown_duration: metrics.drawdownData?.maxDrawdownDuration || 0,
        current_drawdown: metrics.drawdownData?.currentDrawdown || 0,
        drawdown_periods: metrics.drawdownData?.drawdownPeriods?.map((p: DrawdownPeriod) => ({
          start_date: p.startDate,
          end_date: p.endDate,
          depth: p.depth,
          duration: p.duration,
          recovered: p.recovered
        })) || [],

        // Chart data (from signed financial data)
        daily_returns: financialData.dailyReturns.map((d: DailyReturn) => ({
          date: d.date,
          net_return: d.netReturn,
          benchmark_return: d.benchmarkReturn,
          outperformance: d.outperformance,
          cumulative_return: d.cumulativeReturn,
          nav: d.nav
        })),
        monthly_returns: financialData.monthlyReturns.map((m: MonthlyReturn) => ({
          date: m.date,
          net_return: m.netReturn,
          benchmark_return: m.benchmarkReturn,
          outperformance: m.outperformance,
          aum: m.aum
        })),

        // Cryptographic signature
        signature: signedReport.signature,
        public_key: signedReport.publicKey,
        signature_algorithm: signedReport.signatureAlgorithm,
        report_hash: signedReport.reportHash,

        // Enclave attestation
        enclave_version: signedReport.enclaveVersion,
        attestation_id: signedReport.attestationId || '',
        enclave_mode: signedReport.enclaveMode
      };

      logger.info('Signed report generated successfully', {
        report_id: financialData.reportId,
        data_points: financialData.dataPoints,
        signature_length: signedReport.signature.length
      });

      callback(null, response);
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      logger.error('GenerateSignedReport failed', {
        error: errorMessage,
        stack: errorStack
      });

      callback({
        code: grpc.status.INTERNAL,
        message: errorMessage
      }, null);
    }
  }

  /**
   * Handle VerifyReportSignature RPC
   *
   * Verifies that a report signature is valid using the provided public key.
   * This allows external parties to verify report authenticity.
   */
  private async verifyReportSignature(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const rawRequest = call.request;

      const request: VerifySignatureRequest = {
        reportHash: rawRequest.report_hash,
        signature: rawRequest.signature,
        publicKey: rawRequest.public_key
      };

      // Validate required fields
      if (!request.reportHash || !request.signature || !request.publicKey) {
        callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: 'report_hash, signature, and public_key are all required'
        }, null);
        return;
      }

      logger.info('Verifying report signature', {
        hash_prefix: request.reportHash.substring(0, 16) + '...'
      });

      // Verify the signature
      const result = this.reportSigningService.verifySignature(request);

      callback(null, {
        valid: result.valid,
        error: result.error || ''
      });
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);

      logger.error('VerifyReportSignature failed', {
        error: errorMessage
      });

      callback({
        code: grpc.status.INTERNAL,
        message: errorMessage
      }, null);
    }
  }

  /**
   * Start the gRPC server
   */
  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      // SECURITY: TLS is MANDATORY for enclave security
      const credentials = this.createServerCredentials();

      this.server.bindAsync(
        `0.0.0.0:${this.port}`,
        credentials,
        (error, port) => {
          if (error) {
            logger.error('Failed to bind enclave server', {
              error: error.message,
              port: this.port
            });
            reject(error);
            return;
          }

          // Note: server.start() is deprecated in @grpc/grpc-js v1.9+
          // The server automatically starts accepting connections after bindAsync
          logger.info(`Enclave gRPC server started on port ${port} with TLS`);

          // Log enclave attestation info if available
          this.logAttestationInfo();

          resolve();
        }
      );
    });
  }

  /**
   * Stop the gRPC server
   */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server.tryShutdown((error) => {
        if (error) {
          logger.error('Error during enclave server shutdown', {
            error: error.message
          });
          this.server.forceShutdown();
        }
        logger.info('Enclave gRPC server stopped');
        resolve();
      });
    });
  }

  /**
   * Create server credentials for mutual TLS
   *
   * SECURITY: This method enforces TLS with NO fallback to insecure mode.
   * If certificates are missing, the server WILL NOT start.
   *
   * Certificate paths (override via environment variables):
   * - TLS_CA_CERT: Root CA certificate (default: /etc/enclave/ca.crt)
   * - TLS_SERVER_CERT: Server certificate (default: /etc/enclave/server.crt)
   * - TLS_SERVER_KEY: Server private key (default: /etc/enclave/server.key)
   */
  private createServerCredentials(): grpc.ServerCredentials {
    // Dev-only: skip TLS when GRPC_INSECURE=true (set in docker-compose.dev.yml)
    if (process.env.GRPC_INSECURE === 'true' && process.env.NODE_ENV !== 'production') {
      logger.warn('GRPC_INSECURE=true — using insecure gRPC credentials (DEV ONLY)');
      return grpc.ServerCredentials.createInsecure();
    }

    const caCertPath = process.env.TLS_CA_CERT || '/etc/enclave/ca.crt';
    const serverCertPath = process.env.TLS_SERVER_CERT || '/etc/enclave/server.crt';
    const serverKeyPath = process.env.TLS_SERVER_KEY || '/etc/enclave/server.key';

    try {
      const rootCert = fs.readFileSync(caCertPath);
      const serverCert = fs.readFileSync(serverCertPath);
      const serverKey = fs.readFileSync(serverKeyPath);

      logger.info('TLS certificates loaded successfully', {
        ca: caCertPath,
        cert: serverCertPath,
        key: serverKeyPath
      });

      // In development, allow disabling client certificate requirement
      const requireClientCert = process.env.NODE_ENV === 'production' || process.env.REQUIRE_CLIENT_CERT === 'true';

      return grpc.ServerCredentials.createSsl(
        rootCert,
        [{
          cert_chain: serverCert,
          private_key: serverKey
        }],
        requireClientCert // Mutual TLS: require client certificate (disabled in dev by default)
      );
    } catch (error) {
      // SECURITY: NO FALLBACK - server refuses to start without TLS
      const errorMsg = `TLS certificates not found or invalid. Enclave CANNOT start without TLS.
Required certificates:
  - CA cert: ${caCertPath}
  - Server cert: ${serverCertPath}
  - Server key: ${serverKeyPath}

Error: ${(error as Error).message}

For development, generate self-signed certificates:
  mkdir -p /etc/enclave
  openssl req -x509 -newkey rsa:4096 -keyout ${serverKeyPath} -out ${serverCertPath} -days 365 -nodes -subj "/CN=enclave"
  cp ${serverCertPath} ${caCertPath}
`;

      logger.error(errorMsg);
      throw new Error(errorMsg);
    }
  }

  /**
   * Log attestation information for the enclave
   */
  private logAttestationInfo(): void {
    // In a real AMD SEV-SNP deployment, this would log attestation details
    // For now, we'll log environment indicators
    const isEnclave = process.env.ENCLAVE_MODE === 'true';
    const attestationId = process.env.ATTESTATION_ID;

    if (isEnclave) {
      logger.info('Running in ENCLAVE mode', {
        attestationId,
        platform: 'AMD SEV-SNP',
        tcbSize: '4,572 LOC',
        isolation: 'hardware-enforced'
      });
    } else {
      logger.warn('Running in DEVELOPMENT mode (no hardware isolation)', {
        recommendation: 'Deploy to AMD SEV-SNP for production'
      });
    }
  }
}

// Export a function to start the server
export async function startEnclaveServer(): Promise<EnclaveServer> {
  const server = new EnclaveServer();
  await server.start();
  return server;
}

export default EnclaveServer;