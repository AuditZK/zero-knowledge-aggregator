import 'reflect-metadata';
import { setupEnclaveContainer, verifyEnclaveIsolation } from './enclave/config/enclave-container';
import { startEnclaveServer } from './enclave/enclave-server';
import { getPrismaClient } from './config/prisma';
import { logger } from './utils/logger';

const startEnclave = async () => {
  try {
    logger.info('🔒 Starting Enclave Worker (Trusted Zone - SEV-SNP)', {
      version: '3.0.0-enclave',
      environment: process.env.NODE_ENV,
      tcb: '4,572 LOC',
      isolation: 'AMD SEV-SNP',
    });

    // Verify enclave isolation
    const isIsolated = verifyEnclaveIsolation();
    if (!isIsolated) {
      logger.warn('[ENCLAVE] WARNING: Not running in hardware-isolated environment');
      logger.warn('[ENCLAVE] Deploy to AMD SEV-SNP VM for production');
    }

    // Initialize Enclave DI Container (full access to sensitive data)
    logger.info('[ENCLAVE] Initializing DI container...');
    setupEnclaveContainer();
    logger.info('[ENCLAVE] DI container initialized');

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
      tls: process.env.NODE_ENV === 'production' ? 'enabled' : 'disabled',
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