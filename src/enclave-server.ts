import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';
import fs from 'fs';
import { container } from 'tsyringe';
import { EnclaveWorker } from './enclave-worker';
import { getLogger, extractErrorMessage } from './utils/secure-enclave-logger';

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
  private server: grpc.Server;
  private enclaveWorker: EnclaveWorker;
  private port: number;

  constructor() {
    this.server = new grpc.Server();
    this.port = parseInt(process.env.ENCLAVE_PORT || '50051');

    // Get EnclaveWorker instance from DI container
    this.enclaveWorker = container.resolve(EnclaveWorker);

    // Add service implementation
    this.server.addService(enclaveProto.enclave.EnclaveService.service, {
      ProcessSyncJob: this.processSyncJob.bind(this),
      GetAggregatedMetrics: this.getAggregatedMetrics.bind(this),
      GetSnapshotTimeSeries: this.getSnapshotTimeSeries.bind(this),
      CreateUserConnection: this.createUserConnection.bind(this),
      HealthCheck: this.healthCheck.bind(this)
    });

    logger.info('Enclave gRPC server initialized');
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
      const response = {
        snapshots: snapshots.map(snapshot => {
          const bd = snapshot.breakdown as Record<string, any> | undefined;

          // Helper to map market metrics
          const mapMetrics = (data: any) => data ? {
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
   * Start the gRPC server
   */
  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      // SECURITY: TLS is MANDATORY for enclave security
      // No fallback to insecure mode allowed
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

          this.server.start();
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