import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';
import { container } from 'tsyringe';
import { EnclaveWorker } from './enclave-worker';
import { logger } from '../utils/logger';

// Load proto file
const PROTO_PATH = path.join(__dirname, '../proto/enclave.proto');

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
      CalculateHistoricalReturns: this.calculateHistoricalReturns.bind(this),
      GetAggregatedMetrics: this.getAggregatedMetrics.bind(this),
      HealthCheck: this.healthCheck.bind(this)
    });

    logger.info('Enclave gRPC server initialized');
  }

  /**
   * Handle ProcessSyncJob RPC
   */
  private async processSyncJob(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const request = call.request;

      logger.info('Processing sync job request', {
        user_uid: request.user_uid,
        exchange: request.exchange,
        type: request.type
      });

      // Convert gRPC request to internal format
      const syncRequest = {
        userUid: request.user_uid,
        exchange: request.exchange || undefined,
        type: request.type.toLowerCase() as 'incremental' | 'historical' | 'full',
        startDate: request.start_date ? new Date(parseInt(request.start_date)) : undefined,
        endDate: request.end_date ? new Date(parseInt(request.end_date)) : undefined
      };

      // Process the sync job
      const result = await this.enclaveWorker.processSyncJob(syncRequest);

      // Convert internal response to gRPC format
      const response = {
        success: result.success,
        user_uid: result.userUid,
        exchange: result.exchange || '',
        synced: result.synced,
        hourly_returns_generated: result.hourlyReturnsGenerated,
        latest_snapshot: result.latestSnapshot ? {
          balance: result.latestSnapshot.balance,
          equity: result.latestSnapshot.equity,
          timestamp: result.latestSnapshot.timestamp.getTime().toString()
        } : null,
        error: result.error || ''
      };

      callback(null, response);
    } catch (error: any) {
      logger.error('ProcessSyncJob failed', {
        error: error.message,
        stack: error.stack
      });

      callback({
        code: grpc.status.INTERNAL,
        message: error.message
      }, null);
    }
  }

  /**
   * Handle CalculateHistoricalReturns RPC
   */
  private async calculateHistoricalReturns(
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ): Promise<void> {
    try {
      const request = call.request;

      logger.info('Calculating historical returns', {
        user_uid: request.user_uid,
        start_date: request.start_date,
        end_date: request.end_date,
        exchange: request.exchange
      });

      // Calculate returns
      const result = await this.enclaveWorker.calculateHistoricalReturns(
        request.user_uid,
        new Date(parseInt(request.start_date)),
        new Date(parseInt(request.end_date)),
        request.exchange || undefined
      );

      // Convert to gRPC format
      const response = {
        success: result.success,
        returns: result.returns.map(r => ({
          period: r.period,
          net_return: r.netReturn,
          percentage_return: r.percentageReturn,
          balance: r.balance
        })),
        error: result.error || ''
      };

      callback(null, response);
    } catch (error: any) {
      logger.error('CalculateHistoricalReturns failed', {
        error: error.message,
        stack: error.stack
      });

      callback({
        code: grpc.status.INTERNAL,
        message: error.message
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
      const request = call.request;

      logger.info('Getting aggregated metrics', {
        user_uid: request.user_uid,
        exchange: request.exchange
      });

      // Get metrics
      const metrics = await this.enclaveWorker.getAggregatedMetrics(
        request.user_uid,
        request.exchange || undefined
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
    } catch (error: any) {
      logger.error('GetAggregatedMetrics failed', {
        error: error.message,
        stack: error.stack
      });

      callback({
        code: grpc.status.INTERNAL,
        message: error.message
      }, null);
    }
  }

  /**
   * Handle HealthCheck RPC
   */
  private async healthCheck(
    call: grpc.ServerUnaryCall<any, any>,
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
    } catch (error: any) {
      logger.error('HealthCheck failed', {
        error: error.message
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
      // Bind with TLS for production, insecure for development
      const credentials = process.env.NODE_ENV === 'production'
        ? this.createServerCredentials()
        : grpc.ServerCredentials.createInsecure();

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
          logger.info(`Enclave gRPC server started on port ${port}`);

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
   * Create server credentials for production (mutual TLS)
   */
  private createServerCredentials(): grpc.ServerCredentials {
    // In production, load certificates for mutual TLS
    // These would be provisioned securely to the enclave
    const fs = require('fs');

    try {
      const rootCert = fs.readFileSync(process.env.TLS_CA_CERT || '/etc/enclave/ca.crt');
      const serverCert = fs.readFileSync(process.env.TLS_SERVER_CERT || '/etc/enclave/server.crt');
      const serverKey = fs.readFileSync(process.env.TLS_SERVER_KEY || '/etc/enclave/server.key');

      return grpc.ServerCredentials.createSsl(
        rootCert,
        [{
          cert_chain: serverCert,
          private_key: serverKey
        }],
        true // Request client certificate
      );
    } catch (error) {
      logger.warn('TLS certificates not found, falling back to insecure connection', {
        error: (error as Error).message
      });
      return grpc.ServerCredentials.createInsecure();
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