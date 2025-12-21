// Load .env FIRST before anything else
import './env';
import 'reflect-metadata';

import { setupEnclaveContainer, verifyEnclaveIsolation } from './config/enclave-container';
import { startEnclaveServer } from './enclave-server';
import { getPrismaClient } from './config/prisma';
import { getLogger } from './utils/secure-enclave-logger';

const logger = getLogger('Main');
import { MemoryProtectionService } from './services/memory-protection.service';

const startEnclave = async () => {
  try {
    logger.info('🔒 Starting Enclave Worker (Trusted Zone - SEV-SNP)', {
      version: '3.0.0-enclave',
      environment: process.env.NODE_ENV,
      tcb: '4,572 LOC',
      isolation: 'AMD SEV-SNP',
    });

    // SECURITY: Initialize memory protection FIRST (before loading secrets)
    await MemoryProtectionService.initialize();
    const memStatus = MemoryProtectionService.getStatus();
    logger.info('[ENCLAVE] Memory protection status:', memStatus);

    // Log production recommendations if any protections are missing
    const recommendations = MemoryProtectionService.getProductionRecommendations();
    if (recommendations.length > 0 && process.env.NODE_ENV === 'production') {
      logger.warn('[ENCLAVE] ⚠ PRODUCTION SECURITY RECOMMENDATIONS:');
      recommendations.forEach(rec => logger.warn(`  - ${rec}`));
    }

    // Initialize Enclave DI Container SECOND (attestation service needs it)
    logger.info('[ENCLAVE] Initializing DI container...');
    setupEnclaveContainer();
    logger.info('[ENCLAVE] DI container initialized');

    // Generate TLS credentials BEFORE attestation (so fingerprint can be included)
    logger.info('[ENCLAVE] Generating TLS credentials in enclave memory...');
    const { container: diContainer } = await import('tsyringe');
    const { TlsKeyGeneratorService } = await import('./services/tls-key-generator.service');
    const tlsService = diContainer.resolve(TlsKeyGeneratorService);
    const tlsCredentials = await tlsService.getCredentials();

    // Convert fingerprint to Buffer for attestation binding
    const fingerprintHex = tlsCredentials.fingerprint.replace(/:/g, '');
    const fingerprintBuffer = Buffer.from(fingerprintHex, 'hex');

    // Bind TLS fingerprint to attestation service
    const { SevSnpAttestationService } = await import('./services/sev-snp-attestation.service');
    const attestationService = diContainer.resolve(SevSnpAttestationService);
    attestationService.setTlsFingerprint(fingerprintBuffer);

    logger.info('[ENCLAVE] TLS fingerprint bound to attestation', {
      fingerprint: tlsCredentials.fingerprint.slice(0, 23) + '...',
      security: 'Attestation will include TLS cert hash - MITM protection'
    });

    // Initialize E2E encryption service
    logger.info('[ENCLAVE] Initializing E2E encryption (application-level)...');
    const { E2EEncryptionService } = await import('./services/e2e-encryption.service');
    const e2eService = diContainer.resolve(E2EEncryptionService);
    await e2eService.initialize();

    logger.info('[ENCLAVE] E2E encryption initialized', {
      algorithm: 'ECIES (ECDH + AES-256-GCM)',
      publicKeyFingerprint: e2eService.getPublicKeyFingerprint().slice(0, 16) + '...',
      security: 'Double encryption layer - TLS + E2E protects against VPS MITM'
    });

    // Verify enclave isolation with AMD SEV-SNP attestation (now includes TLS fingerprint)
    logger.info('[ENCLAVE] Performing hardware attestation with TLS binding...');
    const attestationResult = await verifyEnclaveIsolation();

    if (!attestationResult.verified) {
      logger.warn('[ENCLAVE] WARNING: Attestation not verified');
      logger.warn(`[ENCLAVE] ${attestationResult.errorMessage}`);

      if (process.env.NODE_ENV === 'production' && process.env.SKIP_ATTESTATION !== 'true') {
        // Attestation failure in production is fatal unless explicitly skipped
        logger.error('[ENCLAVE] ABORTING: Cannot run in production without attestation');
        logger.error('[ENCLAVE] Set SKIP_ATTESTATION=true to bypass (not recommended)');
        process.exit(1);
      }

      if (process.env.SKIP_ATTESTATION === 'true') {
        logger.warn('[ENCLAVE] ⚠️  ATTESTATION BYPASSED - Running without hardware verification');
        logger.warn('[ENCLAVE] This should ONLY be used for development/testing');
      }
    }

    // Initialize Prisma with ENCLAVE user (full permissions)
    logger.info('[ENCLAVE] Connecting to database with full permissions...');
    const prisma = getPrismaClient();

    // Test database connection
    try {
      await prisma.$queryRaw`SELECT 1`;
      logger.info('[ENCLAVE] Database connection established');

      // Verify database access (snapshots only - trades are memory-only)
      const snapshotCount = await prisma.snapshotData.count();
      logger.info('[ENCLAVE] Verified database access', {
        snapshotCount,
        accessLevel: 'AGGREGATED_ONLY',
      });
    } catch (error) {
      logger.error('[ENCLAVE] Database connection failed', error);
      process.exit(1);
    }

    logger.info('[ENCLAVE] Security status:', {
      tradesStorage: '❌ DISABLED (memory only - alpha protection)',
      snapshotsAccess: '✅ ALLOWED (aggregated data)',
      credentialsAccess: '✅ ALLOWED (decrypted in-memory)',
      outputRestriction: 'Aggregated snapshots only',
    });

    // Start gRPC server
    logger.info('[ENCLAVE] Starting gRPC server...');
    const enclaveServer = await startEnclaveServer();

    // Start REST server (auditable user credential submission)
    logger.info('[ENCLAVE] Starting HTTPS REST server...');
    const { startRestServer } = await import('./rest-server');
    const restPort = parseInt(process.env.REST_PORT || '3050', 10);
    const restServer = await startRestServer(restPort);
    // Logs are handled by startRestServer

    // Start HTTP log server (for SSE streaming enclave logs)
    logger.info('[ENCLAVE] Starting HTTP log server for SSE streaming...');
    const { startHttpLogServer } = await import('./http-log-server');
    const { registerSSEBroadcast } = await import('./utils/secure-enclave-logger');
    const httpLogServer = await startHttpLogServer();

    // Register SSE broadcast callback
    registerSSEBroadcast((log) => httpLogServer.broadcastLog(log));

    logger.info('[ENCLAVE] HTTP log server started with SSE streaming');

    // Start Prometheus metrics server (production monitoring)
    if (process.env.METRICS_ENABLED === 'true') {
      logger.info('[ENCLAVE] Starting Prometheus metrics server...');
      const { metricsService } = await import('./services/metrics.service');
      const metricsPort = parseInt(process.env.METRICS_PORT || '9090', 10);
      metricsService.startMetricsServer(metricsPort);
      logger.info('[ENCLAVE] Prometheus metrics available', {
        endpoint: `http://localhost:${metricsPort}/metrics`,
        port: metricsPort
      });

      // Register business metrics collector (called on each scrape)
      const { ExchangeConnectionRepository } = await import('./core/repositories/exchange-connection-repository');
      const connectionRepo = diContainer.resolve(ExchangeConnectionRepository);
      metricsService.registerCollector(async () => {
        const count = await connectionRepo.countAllActiveConnections();
        metricsService.setGauge('exchange_connections_total', count);
      });
      logger.info('[ENCLAVE] Business metrics collectors registered');
    } else {
      logger.info('[ENCLAVE] Metrics server disabled (METRICS_ENABLED=false)');
    }

    // Start Daily Sync Scheduler (autonomous 00:00 UTC sync)
    logger.info('[ENCLAVE] Starting daily sync scheduler...');
    const { DailySyncSchedulerService } = await import('./services/daily-sync-scheduler.service');
    const scheduler = diContainer.resolve(DailySyncSchedulerService);
    scheduler.start();

    const schedulerStatus = scheduler.getStatus();
    logger.info('[ENCLAVE] Daily sync scheduler started', {
      nextSync: schedulerStatus.nextSyncTime.toISOString(),
      timezone: 'UTC',
      schedule: '00:00 UTC daily',
      auditProof: 'Rate-limited (23h cooldown)'
    });

    logger.info('[ENCLAVE] Enclave Worker ready to process sync jobs', {
      grpcPort: process.env.ENCLAVE_PORT || 50051,
      restPort: restPort,
      protocols: 'gRPC (Gateway) + REST (User-Auditable)',
      tls: 'MANDATORY (mutual TLS)',
      attestation: attestationResult.verified ? 'VERIFIED' : 'DEV MODE',
      measurement: attestationResult.measurement || 'N/A',
      autoSync: 'ENABLED (00:00 UTC daily)'
    });

    // Graceful shutdown
    const gracefulShutdown = async (signal: string) => {
      logger.info(`[ENCLAVE] Received ${signal}, shutting down...`);

      const shutdownTimeout = setTimeout(() => {
        logger.error('[ENCLAVE] Shutdown timeout, forcing exit...');
        process.exit(1);
      }, 30000);

      try {
        // Stop daily sync scheduler
        scheduler.stop();

        // Stop HTTP log server
        await httpLogServer.stop();

        // Stop REST server
        await new Promise<void>((resolve, reject) => {
          restServer.close((err) => {
            if (err) reject(err);
            else resolve();
          });
        });

        // Stop Prometheus metrics server
        if (process.env.METRICS_ENABLED === 'true') {
          const { metricsService } = await import('./services/metrics.service');
          metricsService.stopMetricsServer();
        }

        // Stop gRPC server
        await enclaveServer.stop();

        // Close database
        await prisma.$disconnect();

        clearTimeout(shutdownTimeout);
        logger.info('[ENCLAVE] Graceful shutdown completed');
        process.exit(0);
      } catch (error) {
        logger.error('[ENCLAVE] Error during cleanup', error);
        clearTimeout(shutdownTimeout);
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    process.on('unhandledRejection', (reason) => {
      logger.error('[ENCLAVE] Unhandled Rejection:', reason);
      process.exit(1);
    });

    process.on('uncaughtException', (error) => {
      logger.error('[ENCLAVE] Uncaught Exception:', error);
      process.exit(1);
    });

  } catch (error) {
    logger.error('[ENCLAVE] Failed to start', error as Error);
    process.exit(1);
  }
};

// Start the Enclave
startEnclave();