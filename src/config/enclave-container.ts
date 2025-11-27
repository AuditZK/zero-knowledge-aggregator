/**
 * Enclave Dependency Injection Container
 *
 * CRITICAL: This container is used ONLY within the enclave.
 * It contains all services that work with sensitive data:
 * - Encryption/decryption services
 * - Exchange connectors
 * - Aggregated snapshot processing
 *
 * SECURITY: Individual trades are NEVER persisted - only aggregated in memory
 */

import 'reflect-metadata';
import { container } from 'tsyringe';
import { PrismaClient } from '@prisma/client';

// Enclave Services
import { EncryptionService } from '../services/encryption-service';
import { TradeSyncService } from '../services/trade-sync-service';
import { EquitySnapshotAggregator } from '../services/equity-snapshot-aggregator';
import { SyncRateLimiterService } from '../services/sync-rate-limiter.service';
import { DailySyncSchedulerService } from '../services/daily-sync-scheduler.service';
import { SevSnpAttestationService } from '../services/sev-snp-attestation.service';

// External Services (handle credentials)
import { IbkrFlexService } from '../external/ibkr-flex-service';
import { AlpacaApiService } from '../external/alpaca-api-service';

// Repositories (NO TradeRepository - trades are memory-only for alpha protection)
import { SnapshotDataRepository } from '../core/repositories/snapshot-data-repository';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { SyncStatusRepository } from '../core/repositories/sync-status-repository';
import { UserRepository } from '../core/repositories/user-repository';

// Enclave Worker
import { EnclaveWorker } from '../enclave-worker';

// Utils
import { getPrismaClient } from './prisma';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('EnclaveContainer');

/**
 * Configure the Enclave DI container
 *
 * This container has access to:
 * - Encryption keys
 * - Individual trades
 * - Exchange credentials
 * - Sensitive business logic
 */
export function setupEnclaveContainer(): void {
  // Register PrismaClient with enclave-specific configuration
  container.register<PrismaClient>('PrismaClient', {
    useFactory: () => {
      // Use enclave-specific database user with restricted permissions
      // Note: Database URL is configured via environment variables in config/index.ts
      return getPrismaClient();
    }
  });

  // Register Enclave-specific repositories (NO trades - memory only)
  container.registerSingleton(SnapshotDataRepository);
  container.registerSingleton(ExchangeConnectionRepository);
  container.registerSingleton(SyncStatusRepository);
  container.registerSingleton(UserRepository);

  // Register External Services (these handle credentials)
  container.registerSingleton(IbkrFlexService);
  container.registerSingleton(AlpacaApiService);

  // Register Core Enclave Services
  container.registerSingleton(EncryptionService);
  container.registerSingleton(EquitySnapshotAggregator);
  container.registerSingleton(TradeSyncService);
  container.registerSingleton(SyncRateLimiterService);
  container.registerSingleton(DailySyncSchedulerService);
  container.registerSingleton(SevSnpAttestationService);

  // Register Enclave Worker
  container.registerSingleton(EnclaveWorker);

  logger.info('Dependency injection container configured', {
    access_level: 'SENSITIVE',
    capabilities: ['snapshots', 'credentials', 'encryption'],
    security: 'trades_memory_only'
  });
}

/**
 * Get the configured enclave container
 */
export function getEnclaveContainer() {
  return container;
}

/**
 * Clear the enclave container (useful for testing)
 */
export function clearEnclaveContainer(): void {
  container.clearInstances();
}

/**
 * Verify enclave isolation using AMD SEV-SNP attestation
 * Returns attestation result with cryptographic proof
 */
export async function verifyEnclaveIsolation(): Promise<{
  verified: boolean;
  sevSnpEnabled: boolean;
  measurement: string | null;
  errorMessage?: string;
}> {
  const attestationService = container.resolve(SevSnpAttestationService);

  logger.info('Performing AMD SEV-SNP attestation');

  // Get attestation report with cryptographic proof
  const attestationResult = await attestationService.getAttestationReport();

  if (attestationResult.verified) {
    logger.info('AMD SEV-SNP attestation SUCCESSFUL', {
      hardware_isolation: 'VERIFIED',
      tcb_measurement: attestationResult.measurement,
      platform_version: attestationResult.platformVersion,
      sev_snp_enabled: attestationResult.sevSnpEnabled
    });
  } else {
    logger.error('AMD SEV-SNP attestation FAILED', undefined, {
      error_message: attestationResult.errorMessage,
      sev_snp_enabled: attestationResult.sevSnpEnabled
    });

    if (process.env.ENCLAVE_MODE === 'true') {
      logger.error('ENCLAVE_MODE=true but attestation failed - security compromise or misconfiguration');

      // In production, this should ABORT startup
      if (process.env.NODE_ENV === 'production') {
        throw new Error('CRITICAL: Enclave attestation failed in production mode');
      }
    } else {
      logger.warn('Running in DEVELOPMENT mode (no attestation required)', {
        recommendation: 'For production, deploy to AMD SEV-SNP capable hardware'
      });
    }
  }

  return {
    verified: attestationResult.verified,
    sevSnpEnabled: attestationResult.sevSnpEnabled,
    measurement: attestationResult.measurement,
    errorMessage: attestationResult.errorMessage
  };
}

export default setupEnclaveContainer;