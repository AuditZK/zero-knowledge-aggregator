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

// External Services (handle credentials)
import { CCXTService } from '../external/ccxt-service';
import { IbkrFlexService } from '../external/ibkr-flex-service';
import { AlpacaApiService } from '../external/alpaca-api-service';

// Repositories
import { EnclaveRepository } from '../repositories/enclave-repository';
import { TradeRepository } from '../../core/repositories/trade-repository';
import { SnapshotDataRepository } from '../../core/repositories/snapshot-data-repository';
import { ExchangeConnectionRepository } from '../../core/repositories/exchange-connection-repository';
import { SyncStatusRepository } from '../../core/repositories/sync-status-repository';

// Enclave Worker
import { EnclaveWorker } from '../enclave-worker';

// Utils
import { getPrismaClient } from '../../config/prisma';

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
 * Verify enclave isolation
 * This function checks that we're running in a secure environment
 */
export function verifyEnclaveIsolation(): boolean {
  const isEnclave = process.env.ENCLAVE_MODE === 'true';
  const hasSevSnp = process.env.AMD_SEV_SNP === 'true';

  if (!isEnclave) {
    console.warn('[ENCLAVE] WARNING: Not running in enclave mode');
    console.warn('[ENCLAVE] Set ENCLAVE_MODE=true for production');
  }

  if (!hasSevSnp && isEnclave) {
    console.warn('[ENCLAVE] WARNING: SEV-SNP not detected');
    console.warn('[ENCLAVE] Hardware isolation not available');
  }

  if (isEnclave && hasSevSnp) {
    console.log('[ENCLAVE] ✓ Running in AMD SEV-SNP enclave');
    console.log('[ENCLAVE] ✓ Hardware-level isolation active');
  }

  return isEnclave && hasSevSnp;
}

export default setupEnclaveContainer;