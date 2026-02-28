import { injectable, inject } from 'tsyringe';
import { KeyDerivationService } from './key-derivation.service';
import { DEKRepository } from '../repositories/dek-repository';
import { MemoryProtectionService } from './memory-protection.service';
import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';

const logger = getLogger('KeyManagement');

/**
 * Orchestrates DEK lifecycle: initialization, rotation, migration.
 * Master key changes on code updates trigger DEK re-wrapping.
 */
@injectable()
export class KeyManagementService {
  private cachedDEK: Buffer | null = null;

  constructor(
    @inject(KeyDerivationService) private readonly keyDerivation: KeyDerivationService,
    @inject(DEKRepository) private readonly dekRepo: DEKRepository
  ) { }

  /** Returns current DEK, initializing or unwrapping as needed. */
  async getCurrentDEK(): Promise<Buffer> {
    try {
      if (this.cachedDEK) {
        return this.cachedDEK;
      }

      const masterKey = await this.keyDerivation.deriveMasterKey();
      const masterKeyId = this.keyDerivation.getMasterKeyId(masterKey);

      logger.info('Derived master key from SEV-SNP measurement', { masterKeyId });

      const activeDEK = await this.dekRepo.getActiveDEK();

      if (!activeDEK) {
        logger.info('No active DEK found - initializing new DEK system');
        return this.initializeNewDEK(masterKey, masterKeyId);
      }

      if (activeDEK.masterKeyId !== masterKeyId) {
        logger.warn('Master key ID mismatch - code update detected', {
          storedMasterKeyId: activeDEK.masterKeyId,
          currentMasterKeyId: masterKeyId
        });
        throw new Error(
          'Master key mismatch detected - credential migration required. ' +
          'Please run the migration script to re-wrap DEKs with the new master key.'
        );
      }

      const dek = this.keyDerivation.unwrapKey(activeDEK, masterKey);
      this.cachedDEK = dek;

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

  private async initializeNewDEK(masterKey: Buffer, masterKeyId: string): Promise<Buffer> {
    try {
      logger.info('Initializing new DEK system');

      const dek = this.keyDerivation.generateDataEncryptionKey();
      const wrappedDEK = this.keyDerivation.wrapKey(dek, masterKey);

      await this.dekRepo.createDEK({ ...wrappedDEK, masterKeyId });
      this.cachedDEK = dek;

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

  /** Creates new DEK and deactivates old one. */
  async rotateDEK(): Promise<Buffer> {
    try {
      logger.info('Starting DEK rotation');

      const masterKey = await this.keyDerivation.deriveMasterKey();
      const masterKeyId = this.keyDerivation.getMasterKeyId(masterKey);
      const newDEK = this.keyDerivation.generateDataEncryptionKey();
      const wrappedDEK = this.keyDerivation.wrapKey(newDEK, masterKey);

      await this.dekRepo.rotateDEK({ ...wrappedDEK, masterKeyId });
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

  /** Re-wraps DEK with new master key after code update. */
  async migrateDEKToNewMasterKey(oldMasterKey: Buffer): Promise<Buffer> {
    try {
      logger.info('Starting DEK migration to new master key');

      const oldWrappedDEK = await this.dekRepo.getActiveDEK();
      if (!oldWrappedDEK) {
        throw new Error('No active DEK found for migration');
      }

      const dek = this.keyDerivation.unwrapKey(oldWrappedDEK, oldMasterKey);
      logger.info('Successfully unwrapped DEK with old master key');

      const newMasterKey = await this.keyDerivation.deriveMasterKey();
      const newMasterKeyId = this.keyDerivation.getMasterKeyId(newMasterKey);
      const newWrappedDEK = this.keyDerivation.wrapKey(dek, newMasterKey);

      await this.dekRepo.rotateDEK({ ...newWrappedDEK, masterKeyId: newMasterKeyId });
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

  async needsInitialization(): Promise<boolean> {
    const hasActiveDEK = await this.dekRepo.hasActiveDEK();
    return !hasActiveDEK;
  }

  async hasRequiredMigration(): Promise<boolean> {
    try {
      const masterKey = await this.keyDerivation.deriveMasterKey();
      const currentMasterKeyId = this.keyDerivation.getMasterKeyId(masterKey);

      const activeDEK = await this.dekRepo.getActiveDEK();
      if (!activeDEK) {
        return false;
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

  async getCurrentMasterKeyId(): Promise<string> {
    const masterKey = await this.keyDerivation.deriveMasterKey();
    return this.keyDerivation.getMasterKeyId(masterKey);
  }

  clearCache(): void {
    if (this.cachedDEK) {
      MemoryProtectionService.wipeBuffer(this.cachedDEK);
    }
    this.cachedDEK = null;
    logger.info('Key cache cleared (buffer wiped)');
  }

  async isSevSnpAvailable(): Promise<boolean> {
    return this.keyDerivation.isSevSnpAvailable();
  }
}
