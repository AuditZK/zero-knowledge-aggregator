import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';
import fs from 'fs';
import { container } from 'tsyringe';
import { EnclaveWorker } from './enclave-worker';
import { getLogger } from './utils/secure-enclave-logger';
import { createGrpcHandler, normalizeString, normalizeTimestamp } from './utils/grpc-handler';
import { ReportGeneratorService } from './services/report-generator.service';
import { ReportSigningService } from './services/report-signing.service';
import { ReportRequest, VerifySignatureRequest } from './types/report.types';
import {
  SyncJobRequestSchema,
  AggregatedMetricsRequestSchema,
  SnapshotTimeSeriesRequestSchema,
  CreateUserConnectionRequestSchema,
} from './validation/grpc-schemas';

const logger = getLogger('EnclaveServer');

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
  private server: grpc.Server;
  private enclaveWorker: EnclaveWorker;
  private reportGeneratorService: ReportGeneratorService;
  private reportSigningService: ReportSigningService;
  private port: number;

  constructor() {
    this.server = new grpc.Server();
    this.port = parseInt(process.env.ENCLAVE_PORT || '50051');

    // Get service instances from DI container
    this.enclaveWorker = container.resolve(EnclaveWorker);
    this.reportGeneratorService = container.resolve(ReportGeneratorService);
    this.reportSigningService = container.resolve(ReportSigningService);

    // Add service implementation
    this.server.addService(enclaveProto.enclave.EnclaveService.service, {
      ProcessSyncJob: this.processSyncJob.bind(this),
      GetAggregatedMetrics: this.getAggregatedMetrics.bind(this),
      GetSnapshotTimeSeries: this.getSnapshotTimeSeries.bind(this),
      GetPerformanceMetrics: this.getPerformanceMetrics.bind(this),
      CreateUserConnection: this.createUserConnection.bind(this),
      HealthCheck: this.healthCheck.bind(this),
      GenerateSignedReport: this.generateSignedReport.bind(this),
      VerifyReportSignature: this.verifyReportSignature.bind(this)
    });

    logger.info('Enclave gRPC server initialized', {
      publicKeyFingerprint: this.reportSigningService.getPublicKeyFingerprint()
    });
  }

  /** ProcessSyncJob handler using generic wrapper */
  private processSyncJob = createGrpcHandler({
    name: 'ProcessSyncJob',
    schema: SyncJobRequestSchema,
    normalize: (raw: any) => ({
      user_uid: raw.user_uid,
      exchange: normalizeString(raw.exchange),
      type: raw.type || 'incremental'
    }),
    execute: async (validated) => this.enclaveWorker.processSyncJob({
      userUid: validated.user_uid,
      exchange: validated.exchange || undefined
    }),
    toGrpc: (result) => ({
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
    }),
    logFields: (v) => ({ user_uid: v.user_uid, exchange: v.exchange })
  });

  /** GetAggregatedMetrics handler using generic wrapper */
  private getAggregatedMetrics = createGrpcHandler({
    name: 'GetAggregatedMetrics',
    schema: AggregatedMetricsRequestSchema,
    normalize: (raw: any) => ({
      user_uid: raw.user_uid,
      exchange: normalizeString(raw.exchange)
    }),
    execute: async (validated) => this.enclaveWorker.getAggregatedMetrics(
      validated.user_uid,
      validated.exchange || undefined
    ),
    toGrpc: (metrics) => ({
      total_balance: metrics.totalBalance,
      total_equity: metrics.totalEquity,
      total_realized_pnl: metrics.totalRealizedPnl,
      total_unrealized_pnl: metrics.totalUnrealizedPnl,
      total_fees: metrics.totalFees,
      total_trades: metrics.totalTrades,
      last_sync: metrics.lastSync ? metrics.lastSync.getTime().toString() : '0'
    }),
    logFields: (v) => ({ user_uid: v.user_uid, exchange: v.exchange })
  });

  /** GetSnapshotTimeSeries handler using generic wrapper */
  private getSnapshotTimeSeries = createGrpcHandler({
    name: 'GetSnapshotTimeSeries',
    schema: SnapshotTimeSeriesRequestSchema,
    normalize: (raw: any) => ({
      user_uid: raw.user_uid,
      exchange: normalizeString(raw.exchange),
      start_date: normalizeTimestamp(raw.start_date),
      end_date: normalizeTimestamp(raw.end_date)
    }),
    execute: async (validated) => this.enclaveWorker.getSnapshotTimeSeries(
      validated.user_uid,
      validated.exchange || undefined,
      validated.start_date ? new Date(validated.start_date) : undefined,
      validated.end_date ? new Date(validated.end_date) : undefined
    ),
    toGrpc: (snapshots) => {
      const mapMetrics = (data: any) => data ? {
        equity: data.equity || 0, available_margin: data.available_margin || 0,
        volume: data.volume || 0, trades: data.trades || 0,
        trading_fees: data.trading_fees || 0, funding_fees: data.funding_fees || 0
      } : undefined;

      return {
        snapshots: snapshots.map(s => {
          const bd = s.breakdown as Record<string, any> | undefined;
          return {
            user_uid: s.userUid, exchange: s.exchange, timestamp: s.timestamp.getTime(),
            total_equity: s.totalEquity, realized_balance: s.realizedBalance,
            unrealized_pnl: s.unrealizedPnL, deposits: s.deposits, withdrawals: s.withdrawals,
            breakdown: bd ? {
              global: mapMetrics(bd.global), spot: mapMetrics(bd.spot), swap: mapMetrics(bd.swap),
              stocks: mapMetrics(bd.stocks), futures: mapMetrics(bd.futures), cfd: mapMetrics(bd.cfd),
              forex: mapMetrics(bd.forex), commodities: mapMetrics(bd.commodities), options: mapMetrics(bd.options)
            } : undefined
          };
        })
      };
    },
    logFields: (v) => ({ user_uid: v.user_uid, exchange: v.exchange })
  });

  /** CreateUserConnection handler using generic wrapper */
  private createUserConnection = createGrpcHandler({
    name: 'CreateUserConnection',
    schema: CreateUserConnectionRequestSchema,
    normalize: (raw: any) => ({
      user_uid: raw.user_uid,
      exchange: raw.exchange,
      label: raw.label,
      api_key: raw.api_key,
      api_secret: raw.api_secret,
      passphrase: normalizeString(raw.passphrase)
    }),
    execute: async (validated) => this.enclaveWorker.createUserConnection({
      userUid: validated.user_uid,
      exchange: validated.exchange,
      label: validated.label,
      apiKey: validated.api_key,
      apiSecret: validated.api_secret,
      passphrase: validated.passphrase
    }),
    toGrpc: (result) => ({
      success: result.success,
      user_uid: result.userUid || '',
      error: result.error || ''
    }),
    logFields: () => ({}) // Don't log credentials
  });

  /** GetPerformanceMetrics handler - returns statistical metrics only */
  private async getPerformanceMetrics(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const raw = call.request;
      const request = {
        user_uid: raw.user_uid,
        exchange: normalizeString(raw.exchange),
        start_date: normalizeTimestamp(raw.start_date),
        end_date: normalizeTimestamp(raw.end_date)
      };

      logger.info('GetPerformanceMetrics started', { user_uid: request.user_uid, exchange: request.exchange });

      const result = await this.enclaveWorker.getPerformanceMetrics(
        request.user_uid,
        request.exchange,
        request.start_date ? new Date(request.start_date) : undefined,
        request.end_date ? new Date(request.end_date) : undefined
      );

      // Build error response template
      const emptyMetrics = {
        success: false, error: result.error || 'Failed to calculate metrics',
        sharpe_ratio: 0, sortino_ratio: 0, calmar_ratio: 0, volatility: 0,
        downside_deviation: 0, max_drawdown: 0, max_drawdown_duration: 0,
        current_drawdown: 0, win_rate: 0, profit_factor: 0, avg_win: 0, avg_loss: 0,
        period_start: 0, period_end: 0, data_points: 0
      };

      if (!result.success) {
        callback(null, emptyMetrics);
        return;
      }

      const m = result.metrics!;
      callback(null, {
        success: true, error: '',
        sharpe_ratio: m.sharpeRatio || 0, sortino_ratio: m.sortinoRatio || 0,
        calmar_ratio: m.calmarRatio || 0, volatility: m.volatility || 0,
        downside_deviation: m.downsideDeviation || 0, max_drawdown: m.maxDrawdown || 0,
        max_drawdown_duration: m.maxDrawdownDuration || 0, current_drawdown: m.currentDrawdown || 0,
        win_rate: m.winRate || 0, profit_factor: m.profitFactor || 0,
        avg_win: m.avgWin || 0, avg_loss: m.avgLoss || 0,
        period_start: m.periodStart.getTime(), period_end: m.periodEnd.getTime(),
        data_points: m.dataPoints
      });
    } catch (error: unknown) {
      logger.error('GetPerformanceMetrics failed', error);
      callback({ code: grpc.status.INTERNAL, message: error instanceof Error ? error.message : String(error) }, null);
    }
  }

  /** HealthCheck handler - simple health status */
  private async healthCheck(
    _call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const health = await this.enclaveWorker.healthCheck();
      callback(null, {
        status: health.status === 'healthy' ? 0 : 1,
        enclave: health.enclave,
        version: health.version,
        uptime: health.uptime
      });
    } catch {
      callback(null, { status: 1, enclave: true, version: 'error', uptime: 0 });
    }
  }

  /** GenerateSignedReport handler */
  private async generateSignedReport(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const raw = call.request;
      const request: ReportRequest = {
        userUid: raw.user_uid,
        startDate: normalizeString(raw.start_date),
        endDate: normalizeString(raw.end_date),
        benchmark: normalizeString(raw.benchmark) as 'SPY' | 'BTC-USD' | undefined,
        includeRiskMetrics: raw.include_risk_metrics || false,
        includeDrawdown: raw.include_drawdown || false,
        reportName: normalizeString(raw.report_name),
        baseCurrency: raw.base_currency || 'USD'
      };

      if (!request.userUid) {
        callback({ code: grpc.status.INVALID_ARGUMENT, message: 'user_uid is required' }, null);
        return;
      }

      logger.info('GenerateSignedReport started', { user_uid: request.userUid });
      const result = await this.reportGeneratorService.generateSignedReport(request);

      if (!result.success || !result.signedReport) {
        callback(null, { success: false, error: result.error || 'Failed to generate report' });
        return;
      }

      const sr = result.signedReport;
      const rpt = sr.report;
      const m = rpt.metrics;

      callback(null, {
        success: true, error: '',
        report_id: rpt.reportId, user_uid: rpt.userUid, report_name: rpt.reportName,
        generated_at: rpt.generatedAt.toISOString(), period_start: rpt.periodStart.toISOString(),
        period_end: rpt.periodEnd.toISOString(), base_currency: rpt.baseCurrency,
        benchmark: rpt.benchmark || '', data_points: rpt.dataPoints,
        total_return: m.totalReturn, annualized_return: m.annualizedReturn,
        volatility: m.volatility, sharpe_ratio: m.sharpeRatio, sortino_ratio: m.sortinoRatio,
        max_drawdown: m.maxDrawdown, calmar_ratio: m.calmarRatio,
        var_95: m.riskMetrics?.var95 || 0, var_99: m.riskMetrics?.var99 || 0,
        expected_shortfall: m.riskMetrics?.expectedShortfall || 0,
        skewness: m.riskMetrics?.skewness || 0, kurtosis: m.riskMetrics?.kurtosis || 0,
        alpha: m.benchmarkMetrics?.alpha || 0, beta: m.benchmarkMetrics?.beta || 0,
        information_ratio: m.benchmarkMetrics?.informationRatio || 0,
        tracking_error: m.benchmarkMetrics?.trackingError || 0,
        correlation: m.benchmarkMetrics?.correlation || 0,
        max_drawdown_duration: m.drawdownData?.maxDrawdownDuration || 0,
        current_drawdown: m.drawdownData?.currentDrawdown || 0,
        drawdown_periods: m.drawdownData?.drawdownPeriods?.map(p => ({
          start_date: p.startDate, end_date: p.endDate, depth: p.depth,
          duration: p.duration, recovered: p.recovered
        })) || [],
        daily_returns: rpt.dailyReturns.map(d => ({
          date: d.date, net_return: d.netReturn, benchmark_return: d.benchmarkReturn,
          outperformance: d.outperformance, cumulative_return: d.cumulativeReturn, nav: d.nav
        })),
        monthly_returns: rpt.monthlyReturns.map(mo => ({
          date: mo.date, net_return: mo.netReturn, benchmark_return: mo.benchmarkReturn,
          outperformance: mo.outperformance, aum: mo.aum
        })),
        signature: sr.signature, public_key: sr.publicKey,
        signature_algorithm: sr.signatureAlgorithm, report_hash: sr.reportHash,
        enclave_version: sr.enclaveVersion, attestation_id: sr.attestationId || '',
        enclave_mode: sr.enclaveMode
      });
    } catch (error: unknown) {
      logger.error('GenerateSignedReport failed', error);
      callback({ code: grpc.status.INTERNAL, message: error instanceof Error ? error.message : String(error) }, null);
    }
  }

  /** VerifyReportSignature handler */
  private async verifyReportSignature(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const raw = call.request;
      const request: VerifySignatureRequest = {
        reportHash: raw.report_hash,
        signature: raw.signature,
        publicKey: raw.public_key
      };

      if (!request.reportHash || !request.signature || !request.publicKey) {
        callback({ code: grpc.status.INVALID_ARGUMENT, message: 'report_hash, signature, and public_key are required' }, null);
        return;
      }

      const result = this.reportSigningService.verifySignature(request);
      callback(null, { valid: result.valid, error: result.error || '' });
    } catch (error: unknown) {
      logger.error('VerifyReportSignature failed', error);
      callback({ code: grpc.status.INTERNAL, message: error instanceof Error ? error.message : String(error) }, null);
    }
  }

  /**
   * Start the gRPC server
   */
  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const useInsecure = process.env.GRPC_INSECURE === 'true';
      let credentials: grpc.ServerCredentials;

      if (useInsecure) {
        logger.warn('Starting gRPC server in INSECURE mode (development only)');
        credentials = grpc.ServerCredentials.createInsecure();
      } else {
        credentials = this.createServerCredentials();
      }

      this.server.bindAsync(`0.0.0.0:${this.port}`, credentials, (error, port) => {
        if (error) {
          logger.error('Failed to bind enclave server', { error: error.message });
          reject(error);
          return;
        }
        this.server.start();
        logger.info(`Enclave gRPC server started on port ${port} ${useInsecure ? 'INSECURE' : 'with TLS'}`);
        this.logAttestationInfo();
        resolve();
      });
    });
  }

  /** Stop the gRPC server */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server.tryShutdown((error) => {
        if (error) {
          logger.error('Error during shutdown', { error: error.message });
          this.server.forceShutdown();
        }
        logger.info('Enclave gRPC server stopped');
        resolve();
      });
    });
  }

  /** Create mTLS server credentials */
  private createServerCredentials(): grpc.ServerCredentials {
    const caCertPath = process.env.TLS_CA_CERT || '/etc/enclave/ca.crt';
    const serverCertPath = process.env.TLS_SERVER_CERT || '/etc/enclave/server.crt';
    const serverKeyPath = process.env.TLS_SERVER_KEY || '/etc/enclave/server.key';

    try {
      const rootCert = fs.readFileSync(caCertPath);
      const serverCert = fs.readFileSync(serverCertPath);
      const serverKey = fs.readFileSync(serverKeyPath);

      logger.info('TLS certificates loaded');
      const requireClientCert = process.env.NODE_ENV === 'production' || process.env.REQUIRE_CLIENT_CERT === 'true';

      return grpc.ServerCredentials.createSsl(rootCert, [{ cert_chain: serverCert, private_key: serverKey }], requireClientCert);
    } catch (error) {
      const msg = `TLS certificates not found. Required: ${caCertPath}, ${serverCertPath}, ${serverKeyPath}`;
      logger.error(msg);
      throw new Error(msg);
    }
  }

  /** Log attestation info */
  private logAttestationInfo(): void {
    const isEnclave = process.env.ENCLAVE_MODE === 'true';
    if (isEnclave) {
      logger.info('Running in ENCLAVE mode', { platform: 'AMD SEV-SNP' });
    } else {
      logger.warn('Running in DEVELOPMENT mode (no hardware isolation)');
    }
  }
}

export async function startEnclaveServer(): Promise<EnclaveServer> {
  const server = new EnclaveServer();
  await server.start();
  return server;
}

export default EnclaveServer;
