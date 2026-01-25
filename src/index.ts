import './env';
import 'reflect-metadata';

import { setupEnclaveContainer, verifyEnclaveIsolation } from './config/enclave-container';
import { startEnclaveServer } from './enclave-server';
import { connectWithRetry } from './config/prisma';
import { getLogger } from './utils/secure-enclave-logger';
import { MemoryProtectionService } from './services/memory-protection.service';

const logger = getLogger('Main');

const startEnclave = async () => {
  try {
    logger.info('Starting Enclave Worker (SEV-SNP)', {
      version: '3.0.0-enclave',
      environment: process.env.NODE_ENV,
    });

    // 1. Memory protection first (before loading secrets)
    await MemoryProtectionService.initialize();
    logger.info('Memory protection status:', MemoryProtectionService.getStatus());

    const recommendations = MemoryProtectionService.getProductionRecommendations();
    if (recommendations.length > 0 && process.env.NODE_ENV === 'production') {
      recommendations.forEach(rec => logger.warn(`Security recommendation: ${rec}`));
    }

    // 2. DI container
    setupEnclaveContainer();
    logger.info('DI container initialized');

    // 3. TLS credentials (before attestation for fingerprint binding)
    const { container: diContainer } = await import('tsyringe');
    const { TlsKeyGeneratorService } = await import('./services/tls-key-generator.service');
    const tlsService = diContainer.resolve(TlsKeyGeneratorService);
    const tlsCredentials = await tlsService.getCredentials();

    const fingerprintHex = tlsCredentials.fingerprint.replaceAll(':', '');
    const fingerprintBuffer = Buffer.from(fingerprintHex, 'hex');

    const { SevSnpAttestationService } = await import('./services/sev-snp-attestation.service');
    const attestationService = diContainer.resolve(SevSnpAttestationService);
    attestationService.setTlsFingerprint(fingerprintBuffer);

    logger.info('TLS fingerprint bound to attestation', {
      fingerprint: tlsCredentials.fingerprint.slice(0, 23) + '...',
    });

    // 4. E2E encryption
    const { E2EEncryptionService } = await import('./services/e2e-encryption.service');
    const e2eService = diContainer.resolve(E2EEncryptionService);
    await e2eService.initialize();

    logger.info('E2E encryption initialized', {
      algorithm: 'ECIES (ECDH + AES-256-GCM)',
      publicKeyFingerprint: e2eService.getPublicKeyFingerprint().slice(0, 16) + '...',
    });

    // 5. Hardware attestation
    const attestationResult = await verifyEnclaveIsolation();

    if (!attestationResult.verified) {
      logger.warn('Attestation not verified', { errorMessage: attestationResult.errorMessage });

      if (process.env.NODE_ENV === 'production') {
        logger.error('FATAL: Cannot run in production without hardware attestation');
        process.exit(1);
      }

      if (process.env.SKIP_ATTESTATION === 'true') {
        logger.warn('ATTESTATION BYPASSED - Development mode only');
      }
    }

    // 6. Database (with two-phase retry: fast then slow over ~1 hour)
    let prisma;
    try {
      const { client, snapshotCount } = await connectWithRetry();
      prisma = client;
      logger.info('Database connected', { snapshotCount });
    } catch (error) {
      logger.error('Database connection failed after all retries (~1 hour)', error);
      process.exit(1);
    }

    // 7. gRPC server
    const enclaveServer = await startEnclaveServer();

    // 8. REST server
    const { startRestServer } = await import('./rest-server');
    const restPort = Number.parseInt(process.env.REST_PORT || '3050', 10);
    const restServer = await startRestServer(restPort);

    // 9. HTTP log server (SSE)
    const { startHttpLogServer } = await import('./http-log-server');
    const { registerSSEBroadcast } = await import('./utils/secure-enclave-logger');
    const httpLogServer = await startHttpLogServer();
    registerSSEBroadcast((log) => httpLogServer.broadcastLog(log));

    // 10. Prometheus metrics
    if (process.env.METRICS_ENABLED === 'true') {
      const { metricsService } = await import('./services/metrics.service');
      const metricsPort = Number.parseInt(process.env.METRICS_PORT || '9090', 10);
      metricsService.startMetricsServer(metricsPort);

      const { ExchangeConnectionRepository } = await import('./core/repositories/exchange-connection-repository');
      const connectionRepo = diContainer.resolve(ExchangeConnectionRepository);
      metricsService.registerCollector(async () => {
        const count = await connectionRepo.countAllActiveConnections();
        metricsService.setGauge('exchange_connections_total', count);
      });
    }

    // 11. Daily sync scheduler
    const { DailySyncSchedulerService } = await import('./services/daily-sync-scheduler.service');
    const scheduler = diContainer.resolve(DailySyncSchedulerService);
    scheduler.start();

    logger.info('Enclave Worker ready', {
      grpcPort: process.env.ENCLAVE_PORT || 50051,
      restPort,
      attestation: attestationResult.verified ? 'VERIFIED' : 'DEV_MODE',
      nextSync: scheduler.getStatus().nextSyncTime.toISOString(),
    });

    // Graceful shutdown
    const gracefulShutdown = async (signal: string) => {
      logger.info(`Received ${signal}, shutting down...`);

      const shutdownTimeout = setTimeout(() => {
        logger.error('Shutdown timeout, forcing exit...');
        process.exit(1);
      }, 30000);

      try {
        scheduler.stop();
        await httpLogServer.stop();
        await new Promise<void>((resolve, reject) => {
          restServer.close((err) => err ? reject(err) : resolve());
        });
        if (process.env.METRICS_ENABLED === 'true') {
          const { metricsService } = await import('./services/metrics.service');
          metricsService.stopMetricsServer();
        }
        await enclaveServer.stop();
        await prisma.$disconnect();

        clearTimeout(shutdownTimeout);
        logger.info('Graceful shutdown completed');
        process.exit(0);
      } catch (error) {
        logger.error('Error during cleanup', error);
        clearTimeout(shutdownTimeout);
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled Rejection:', reason);
      process.exit(1);
    });
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      process.exit(1);
    });

  } catch (error) {
    logger.error('Failed to start enclave', error as Error);
    process.exit(1);
  }
};

startEnclave();
