/**
 * Enclave Dependency Injection Container
 *
 * CRITICAL: This container is used ONLY within the enclave.
 * It contains all services that work with sensitive data:
 * - Encryption/decryption services
 * - Exchange connectors
 * - Trade processing
 * - Individual trade access
 */

import 'reflect-metadata';
import { container } from 'tsyringe';
import { PrismaClient } from '@prisma/client';

// Enclave Services
import { EncryptionService } from '../services/encryption-service';
import { TradeSyncService } from '../services/trade-sync-service';
import { EquitySnapshotAggregator } from '../services/equity-snapshot-aggregator';
import { SevSnpAttestationService } from '../services/sev-snp-attestation.service';

// External Services (handle credentials)
import { CCXTService } from '../external/ccxt-service';
import { IbkrFlexService } from '../external/ibkr-flex-service';
import { AlpacaApiService } from '../external/alpaca-api-service';

// Repositories
import { EnclaveRepository } from '../repositories/enclave-repository';
import { TradeRepository } from '../core/repositories/trade-repository';
import { SnapshotDataRepository } from '../core/repositories/snapshot-data-repository';
import { ExchangeConnectionRepository } from '../core/repositories/exchange-connection-repository';
import { SyncStatusRepository } from '../core/repositories/sync-status-repository';

// Enclave Worker
import { EnclaveWorker } from '../enclave-worker';

// Utils
import { getPrismaClient } from './prisma';

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
      const databaseUrl = process.env.ENCLAVE_DATABASE_URL || process.env.DATABASE_URL;
      return getPrismaClient(databaseUrl);
    }
  });

  // Register Enclave-specific repositories
  container.registerSingleton(EnclaveRepository);
  container.registerSingleton(TradeRepository);
  container.registerSingleton(SnapshotDataRepository);
  container.registerSingleton(ExchangeConnectionRepository);
  container.registerSingleton(SyncStatusRepository);

  // Register External Services (these handle credentials)
  container.registerSingleton(CCXTService);
  container.registerSingleton(IbkrFlexService);
  container.registerSingleton(AlpacaApiService);

  // Register Core Enclave Services
  container.registerSingleton(EncryptionService);
  container.registerSingleton(EquitySnapshotAggregator);
  container.registerSingleton(TradeSyncService);
  container.registerSingleton(SevSnpAttestationService);

  // Register Enclave Worker
  container.registerSingleton(EnclaveWorker);

  console.log('[ENCLAVE] Dependency injection container configured');
  console.log('[ENCLAVE] TCB: ~4,572 LOC');
  console.log('[ENCLAVE] Access level: SENSITIVE (trades, credentials)');
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

  console.log('[ENCLAVE] Performing AMD SEV-SNP attestation...');

  // Get attestation report with cryptographic proof
  const attestationResult = await attestationService.getAttestationReport();

  if (attestationResult.verified) {
    console.log('[ENCLAVE] ✓ AMD SEV-SNP attestation SUCCESSFUL');
    console.log('[ENCLAVE] ✓ Hardware-level isolation VERIFIED');
    console.log(`[ENCLAVE] ✓ TCB Measurement: ${attestationResult.measurement}`);
    console.log(`[ENCLAVE] ✓ Platform Version: ${attestationResult.platformVersion}`);
  } else {
    console.error('[ENCLAVE] ✗ AMD SEV-SNP attestation FAILED');
    console.error(`[ENCLAVE] ✗ Error: ${attestationResult.errorMessage}`);

    if (process.env.ENCLAVE_MODE === 'true') {
      console.error('[ENCLAVE] ✗ ENCLAVE_MODE=true but attestation failed');
      console.error('[ENCLAVE] ✗ This indicates a security compromise or misconfiguration');

      // In production, this should ABORT startup
      if (process.env.NODE_ENV === 'production') {
        throw new Error('CRITICAL: Enclave attestation failed in production mode');
      }
    } else {
      console.warn('[ENCLAVE] ⚠ Running in DEVELOPMENT mode (no attestation required)');
      console.warn('[ENCLAVE] ⚠ For production, deploy to AMD SEV-SNP capable hardware');
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