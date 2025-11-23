import 'reflect-metadata';
import { setupEnclaveContainer, verifyEnclaveIsolation } from './config/enclave-container';
import { startEnclaveServer } from './enclave-server';
import { getPrismaClient } from './config/prisma';
import { logger } from './utils/logger';
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

    // Verify enclave isolation with AMD SEV-SNP attestation
    logger.info('[ENCLAVE] Performing hardware attestation...');
    const attestationResult = await verifyEnclaveIsolation();

    if (!attestationResult.verified) {
      logger.warn('[ENCLAVE] WARNING: Attestation not verified');
      logger.warn(`[ENCLAVE] ${attestationResult.errorMessage}`);

      if (process.env.NODE_ENV === 'production') {
        // Attestation failure in production is fatal
        logger.error('[ENCLAVE] ABORTING: Cannot run in production without attestation');
        process.exit(1);
      }
    }

    // Initialize Prisma with ENCLAVE user (full permissions)
    logger.info('[ENCLAVE] Connecting to database with full permissions...');
    const prisma = getPrismaClient();

    // Test database connection
    try {
      await prisma.$queryRaw`SELECT 1`;
      logger.info('[ENCLAVE] Database connection established');

      // Verify we can access trades (enclave only)
      const tradeCount = await prisma.trade.count();
      logger.info('[ENCLAVE] Verified access to sensitive data', {
        tradeCount,
        accessLevel: 'FULL',
      });
    } catch (error) {
      logger.error('[ENCLAVE] Database connection failed', error);
      process.exit(1);
    }

    logger.info('[ENCLAVE] Security status:', {
      tradesAccess: '✅ ALLOWED (Enclave only)',
      credentialsAccess: '✅ ALLOWED (Decrypted in-memory)',
      encryptionKeys: '✅ LOADED',
      outputRestriction: 'Aggregated data only',
    });

    // Start gRPC server
    logger.info('[ENCLAVE] Starting gRPC server...');
    const enclaveServer = await startEnclaveServer();

    logger.info('[ENCLAVE] Enclave Worker ready to process sync jobs', {
      protocol: 'gRPC',
      port: process.env.ENCLAVE_PORT || 50051,
      tls: 'MANDATORY (mutual TLS)',
      attestation: attestationResult.verified ? 'VERIFIED' : 'DEV MODE',
      measurement: attestationResult.measurement || 'N/A'
    });

    // Graceful shutdown
    const gracefulShutdown = async (signal: string) => {
      logger.info(`[ENCLAVE] Received ${signal}, shutting down...`);

      const shutdownTimeout = setTimeout(() => {
        logger.error('[ENCLAVE] Shutdown timeout, forcing exit...');
        process.exit(1);
      }, 30000);

      try {
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