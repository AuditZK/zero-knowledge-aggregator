import { injectable, inject } from 'tsyringe';
import { KeyDerivationService } from './key-derivation.service';
import { DEKRepository } from '../repositories/dek-repository';
import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';

const logger = getLogger('KeyManagement');

/**
 * Key Management Service - Orchestrates DEK lifecycle and versioning
 *
 * RESPONSIBILITIES:
 * - Initialize DEK system on first run
 * - Detect master key changes (code updates)
 * - Automatic DEK rotation on master key change
 * - Provide unified interface for current DEK access
 * - Migration coordination
 *
 * VERSIONING STRATEGY:
 * - Master Key = f(AMD SEV-SNP measurement) → changes with code updates
 * - Master Key ID = hash(Master Key) → identifies which version
 * - DEK rotation triggered when Master Key ID changes
 * - Old credentials re-encrypted automatically with new DEK
 */
@injectable()
export class KeyManagementService {
  // private cachedMasterKey: Buffer | null = null;
  // private cachedMasterKeyId: string | null = null;
  private cachedDEK: Buffer | null = null;

  constructor(
    @inject(KeyDerivationService) private keyDerivation: KeyDerivationService,
    @inject(DEKRepository) private dekRepo: DEKRepository
  ) { }

  /**
   * Gets the current Data Encryption Key, initializing if needed
   *
   * This is the main entry point for encryption/decryption operations.
   * Handles:
   * - First-time initialization
   * - Master key change detection
   * - Automatic DEK rotation
   * - Caching for performance
   *
   * @returns Current active DEK
   * @throws Error if SEV-SNP not available or initialization fails
   */
  async getCurrentDEK(): Promise<Buffer> {
    try {
      // Return cached DEK if available (avoids DB queries on every operation)
      if (this.cachedDEK) {
        return this.cachedDEK;
      }

      // Derive master key from hardware
      const masterKey = await this.keyDerivation.deriveMasterKey();
      const masterKeyId = this.keyDerivation.getMasterKeyId(masterKey);

      logger.info('Derived master key from SEV-SNP measurement', { masterKeyId });

      // Check if we have an active DEK
      const activeDEK = await this.dekRepo.getActiveDEK();

      if (!activeDEK) {
        // First-time initialization - create new DEK
        logger.info('No active DEK found - initializing new DEK system');
        return this.initializeNewDEK(masterKey, masterKeyId);
      }

      // Check if master key has changed (code update)
      if (activeDEK.masterKeyId !== masterKeyId) {
        logger.warn('Master key ID mismatch - code update detected', {
          storedMasterKeyId: activeDEK.masterKeyId,
          currentMasterKeyId: masterKeyId
        });

        // This indicates enclave code was updated
        // DEK needs to be re-wrapped with new master key
        throw new Error(
          'Master key mismatch detected - credential migration required. ' +
          'Please run the migration script to re-wrap DEKs with the new master key.'
        );
      }

      // Unwrap DEK with current master key
      const dek = this.keyDerivation.unwrapKey(activeDEK, masterKey);

      // Cache for performance
      this.cachedDEK = dek;
      // this.cachedMasterKey = masterKey;
      // this.cachedMasterKeyId = masterKeyId;

      logger.info('Successfully retrieved and unwrapped active DEK', {
        dekId: activeDEK.id,
        keyVersion: activeDEK.keyVersion
      });

      return dek;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to get current DEK', { error: errorMessage });
      throw error;
    }
  }

  /**
   * Initializes a new DEK (first-time setup)
   *
   * Creates:
   * 1. Random DEK
   * 2. Wraps it with current master key
   * 3. Stores in database
   * 4. Caches for performance
   *
   * @param masterKey Current master key
   * @param masterKeyId Master key identifier
   * @returns Newly created DEK
   */
  private async initializeNewDEK(masterKey: Buffer, masterKeyId: string): Promise<Buffer> {
    try {
      logger.info('Initializing new DEK system');

      // Generate random DEK
      const dek = this.keyDerivation.generateDataEncryptionKey();

      // Wrap DEK with master key
      const wrappedDEK = this.keyDerivation.wrapKey(dek, masterKey);

      // Store in database
      await this.dekRepo.createDEK({
        ...wrappedDEK,
        masterKeyId
      });

      // Cache for performance
      this.cachedDEK = dek;
      // this.cachedMasterKey = masterKey;
      // this.cachedMasterKeyId = masterKeyId;

      logger.info('DEK system initialized successfully', {
        masterKeyId,
        keyVersion: wrappedDEK.keyVersion
      });

      return dek;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to initialize new DEK', { error: errorMessage });
      throw error;
    }
  }

  /**
   * Rotates the DEK (creates new DEK, deactivates old one)
   *
   * Used for:
   * - Manual rotation (security policy)
   * - Master key migration (after code update)
   *
   * NOTE: This only rotates the DEK wrapper, not the credentials.
   * Credential re-encryption is handled by migration script.
   *
   * @returns New active DEK
   */
  async rotateDEK(): Promise<Buffer> {
    try {
      logger.info('Starting DEK rotation');

      // Derive current master key
      const masterKey = await this.keyDerivation.deriveMasterKey();
      const masterKeyId = this.keyDerivation.getMasterKeyId(masterKey);

      // Generate new random DEK
      const newDEK = this.keyDerivation.generateDataEncryptionKey();

      // Wrap with current master key
      const wrappedDEK = this.keyDerivation.wrapKey(newDEK, masterKey);

      // Store in database (automatically deactivates old DEK)
      await this.dekRepo.rotateDEK({
        ...wrappedDEK,
        masterKeyId
      });

      // Clear cache (force reload on next access)
      this.clearCache();

      logger.info('DEK rotation completed successfully', {
        masterKeyId,
        keyVersion: wrappedDEK.keyVersion
      });

      return newDEK;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to rotate DEK', { error: errorMessage });
      throw error;
    }
  }

  /**
   * Migrates DEK to new master key (after code update)
   *
   * This is the critical operation after enclave code update:
   * 1. Unwrap old DEK with OLD master key (stored in migration script)
   * 2. Re-wrap same DEK with NEW master key (current hardware measurement)
   * 3. Update database
   *
   * @param oldMasterKey Previous master key (before code update)
   * @returns Migrated DEK
   */
  async migrateDEKToNewMasterKey(oldMasterKey: Buffer): Promise<Buffer> {
    try {
      logger.info('Starting DEK migration to new master key');

      // Get current active DEK (wrapped with OLD master key)
      const oldWrappedDEK = await this.dekRepo.getActiveDEK();
      if (!oldWrappedDEK) {
        throw new Error('No active DEK found for migration');
      }

      // Unwrap DEK using OLD master key
      const dek = this.keyDerivation.unwrapKey(oldWrappedDEK, oldMasterKey);

      logger.info('Successfully unwrapped DEK with old master key');

      // Derive NEW master key from current hardware
      const newMasterKey = await this.keyDerivation.deriveMasterKey();
      const newMasterKeyId = this.keyDerivation.getMasterKeyId(newMasterKey);

      // Re-wrap same DEK with NEW master key
      const newWrappedDEK = this.keyDerivation.wrapKey(dek, newMasterKey);

      // Store new wrapped version
      await this.dekRepo.rotateDEK({
        ...newWrappedDEK,
        masterKeyId: newMasterKeyId
      });

      // Clear cache
      this.clearCache();

      logger.info('DEK migration completed successfully', {
        oldMasterKeyId: oldWrappedDEK.masterKeyId,
        newMasterKeyId
      });

      return dek;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to migrate DEK to new master key', { error: errorMessage });
      throw error;
    }
  }

  /**
   * Checks if DEK system needs initialization
   *
   * @returns true if no active DEK exists
   */
  async needsInitialization(): Promise<boolean> {
    const hasActiveDEK = await this.dekRepo.hasActiveDEK();
    return !hasActiveDEK;
  }

  /**
   * Checks if master key has changed (code update detected)
   *
   * @returns true if master key ID mismatch detected
   */
  async hasRequiredMigration(): Promise<boolean> {
    try {
      const masterKey = await this.keyDerivation.deriveMasterKey();
      const currentMasterKeyId = this.keyDerivation.getMasterKeyId(masterKey);

      const activeDEK = await this.dekRepo.getActiveDEK();
      if (!activeDEK) {
        return false; // No DEK = needs initialization, not migration
      }

      const mismatch = activeDEK.masterKeyId !== currentMasterKeyId;

      if (mismatch) {
        logger.warn('Master key mismatch detected - migration required', {
          storedMasterKeyId: activeDEK.masterKeyId,
          currentMasterKeyId
        });
      }

      return mismatch;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to check migration requirement', { error: errorMessage });
      throw error;
    }
  }

  /**
   * Gets current master key ID for diagnostic purposes
   *
   * @returns Master key identifier (hash, not the key itself)
   */
  async getCurrentMasterKeyId(): Promise<string> {
    const masterKey = await this.keyDerivation.deriveMasterKey();
    return this.keyDerivation.getMasterKeyId(masterKey);
  }

  /**
   * Clears cached keys (forces reload on next access)
   *
   * Call after rotation or migration to ensure fresh keys are used
   */
  clearCache(): void {
    this.cachedDEK = null;
    // this.cachedMasterKey = null;
    // this.cachedMasterKeyId = null;
    logger.info('Key cache cleared');
  }

  /**
   * Checks if SEV-SNP key derivation is available
   *
   * @returns true if hardware is available, false otherwise
   */
  async isSevSnpAvailable(): Promise<boolean> {
    return this.keyDerivation.isSevSnpAvailable();
  }
}
