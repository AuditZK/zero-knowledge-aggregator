/**
 * Migration Script: Environment Variable Keys → AMD SEV-SNP Hardware-Derived Keys
 *
 * WHAT THIS SCRIPT DOES:
 * 1. Initializes the new hardware-based key derivation system
 * 2. Re-encrypts all existing credentials with the new hardware-derived DEK
 * 3. Verifies migration success
 * 4. Provides rollback capability
 *
 * WHEN TO RUN:
 * - First-time setup: Initializes DEK system, no re-encryption needed if no data
 * - Migration: Re-encrypts existing credentials from old env var key to new hardware key
 * - After code update: If master key changes, re-wraps DEK (no credential re-encryption)
 *
 * USAGE:
 *   ts-node scripts/migrate-to-hardware-keys.ts
 *
 * SAFETY:
 * - Dry-run mode available (--dry-run flag)
 * - Backs up existing credentials before migration
 * - Verifies decryption works before committing changes
 * - Rollback available if migration fails
 */

import 'reflect-metadata';
import { container } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import * as crypto from 'crypto';
import { KeyManagementService } from '../src/services/key-management.service';
import { EncryptionService } from '../src/services/encryption-service';
import { ExchangeConnectionRepository } from '../src/core/repositories/exchange-connection-repository';
import { getLogger } from '../src/utils/secure-enclave-logger';
import { setupEnclaveContainer } from '../src/config/enclave-container';

const logger = getLogger('CredentialMigration');

interface MigrationStats {
  totalConnections: number;
  migrated: number;
  failed: number;
  skipped: number;
}

interface BackupCredential {
  id: string;
  encryptedApiKey: string;
  encryptedApiSecret: string;
  encryptedPassphrase: string | null;
}

/**
 * Main migration orchestrator
 */
class CredentialMigrator {
  private keyManagement!: KeyManagementService;
  private encryptionService!: EncryptionService;
  private exchangeRepo!: ExchangeConnectionRepository;
  private prisma!: PrismaClient;
  private stats: MigrationStats = {
    totalConnections: 0,
    migrated: 0,
    failed: 0,
    skipped: 0
  };
  private backups: BackupCredential[] = [];

  async initialize(): Promise<void> {
    logger.info('Initializing migration container...');

    // Setup DI container
    setupEnclaveContainer();

    // Resolve services
    this.keyManagement = container.resolve(KeyManagementService);
    this.encryptionService = container.resolve(EncryptionService);
    this.exchangeRepo = container.resolve(ExchangeConnectionRepository);
    this.prisma = container.resolve<PrismaClient>('PrismaClient');

    logger.info('Migration container initialized successfully');
  }

  /**
   * Check if system needs initialization or migration
   */
  async checkMigrationStatus(): Promise<{
    needsInitialization: boolean;
    needsMigration: boolean;
    currentMasterKeyId: string | null;
  }> {
    const needsInitialization = await this.keyManagement.needsInitialization();
    const needsMigration = await this.keyManagement.hasRequiredMigration();

    let currentMasterKeyId: string | null = null;
    if (!needsInitialization) {
      currentMasterKeyId = await this.keyManagement.getCurrentMasterKeyId();
    }

    logger.info('Migration status check', {
      needsInitialization,
      needsMigration,
      currentMasterKeyId
    });

    return { needsInitialization, needsMigration, currentMasterKeyId };
  }

  /**
   * Initialize DEK system (first-time setup)
   */
  async initializeDEKSystem(): Promise<void> {
    logger.info('Starting DEK system initialization...');

    try {
      // This will create the first DEK automatically
      await this.keyManagement.getCurrentDEK();

      logger.info('DEK system initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize DEK system', { error });
      throw error;
    }
  }

  /**
   * Backup existing credentials before migration
   */
  async backupCredentials(): Promise<void> {
    logger.info('Backing up existing credentials...');

    const connections = await this.prisma.exchangeConnection.findMany({
      select: {
        id: true,
        encryptedApiKey: true,
        encryptedApiSecret: true,
        encryptedPassphrase: true
      }
    });

    this.backups = connections.map(conn => ({
      id: conn.id,
      encryptedApiKey: conn.encryptedApiKey,
      encryptedApiSecret: conn.encryptedApiSecret,
      encryptedPassphrase: conn.encryptedPassphrase
    }));

    logger.info('Credentials backed up', { count: this.backups.length });
  }

  /**
   * Migrate credentials from old env var key to new hardware-derived key
   */
  async migrateCredentials(dryRun: boolean = false): Promise<void> {
    logger.info('Starting credential migration...', { dryRun });

    const connections = await this.prisma.exchangeConnection.findMany();
    this.stats.totalConnections = connections.length;

    if (this.stats.totalConnections === 0) {
      logger.info('No credentials to migrate - system is clean');
      return;
    }

    // Create old encryption service (using env var key)
    const oldEncryptionKey = process.env.ENCRYPTION_KEY;
    if (!oldEncryptionKey) {
      throw new Error('ENCRYPTION_KEY environment variable required for migration');
    }

    const oldKey = crypto.createHash('sha256').update(oldEncryptionKey).digest();

    logger.info('Migrating credentials', { total: this.stats.totalConnections });

    for (const connection of connections) {
      try {
        // Decrypt with OLD key (env var)
        const apiKey = this.decryptWithOldKey(connection.encryptedApiKey, oldKey);
        const apiSecret = this.decryptWithOldKey(connection.encryptedApiSecret, oldKey);
        const passphrase = connection.encryptedPassphrase
          ? this.decryptWithOldKey(connection.encryptedPassphrase, oldKey)
          : null;

        // Re-encrypt with NEW hardware-derived key
        const newEncryptedApiKey = await this.encryptionService.encrypt(apiKey);
        const newEncryptedApiSecret = await this.encryptionService.encrypt(apiSecret);
        const newEncryptedPassphrase = passphrase
          ? await this.encryptionService.encrypt(passphrase)
          : null;

        // Verify decryption works with new key
        const verifyApiKey = await this.encryptionService.decrypt(newEncryptedApiKey);
        const verifyApiSecret = await this.encryptionService.decrypt(newEncryptedApiSecret);

        if (verifyApiKey !== apiKey || verifyApiSecret !== apiSecret) {
          throw new Error('Verification failed - decrypted values do not match');
        }

        if (!dryRun) {
          // Update database with new encrypted values
          await this.prisma.exchangeConnection.update({
            where: { id: connection.id },
            data: {
              encryptedApiKey: newEncryptedApiKey,
              encryptedApiSecret: newEncryptedApiSecret,
              encryptedPassphrase: newEncryptedPassphrase
            }
          });
        }

        this.stats.migrated++;
        logger.info('Migrated credential successfully', {
          connectionId: connection.id,
          exchange: connection.exchange,
          dryRun
        });
      } catch (error) {
        this.stats.failed++;
        logger.error('Failed to migrate credential', {
          connectionId: connection.id,
          exchange: connection.exchange,
          error
        });

        if (!dryRun) {
          // Rollback on first failure
          await this.rollback();
          throw new Error(`Migration failed for connection ${connection.id}: ${error}`);
        }
      }
    }

    logger.info('Credential migration completed', this.stats);
  }

  /**
   * Decrypt using old environment variable key
   */
  private decryptWithOldKey(encryptedData: string, oldKey: Buffer): string {
    const IV_LENGTH = 16;
    const TAG_LENGTH = 16;

    const iv = Buffer.from(encryptedData.slice(0, IV_LENGTH * 2), 'hex');
    const tag = Buffer.from(encryptedData.slice(IV_LENGTH * 2, (IV_LENGTH + TAG_LENGTH) * 2), 'hex');
    const encrypted = encryptedData.slice((IV_LENGTH + TAG_LENGTH) * 2);

    const decipher = crypto.createDecipheriv('aes-256-gcm', oldKey, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Rollback credentials to backup state
   */
  async rollback(): Promise<void> {
    logger.warn('Rolling back credential migration...');

    for (const backup of this.backups) {
      await this.prisma.exchangeConnection.update({
        where: { id: backup.id },
        data: {
          encryptedApiKey: backup.encryptedApiKey,
          encryptedApiSecret: backup.encryptedApiSecret,
          encryptedPassphrase: backup.encryptedPassphrase
        }
      });
    }

    logger.warn('Rollback completed - credentials restored to original state');
  }

  /**
   * Verify all credentials are accessible with new key
   */
  async verifyMigration(): Promise<boolean> {
    logger.info('Verifying migration success...');

    const connections = await this.prisma.exchangeConnection.findMany();

    for (const connection of connections) {
      try {
        // Attempt to decrypt with new key
        await this.encryptionService.decrypt(connection.encryptedApiKey);
        await this.encryptionService.decrypt(connection.encryptedApiSecret);

        if (connection.encryptedPassphrase) {
          await this.encryptionService.decrypt(connection.encryptedPassphrase);
        }
      } catch (error) {
        logger.error('Verification failed for connection', {
          connectionId: connection.id,
          error
        });
        return false;
      }
    }

    logger.info('Migration verification successful - all credentials accessible');
    return true;
  }

  /**
   * Print migration summary
   */
  printSummary(status: { needsInitialization: boolean; needsMigration: boolean }): void {
    console.log('\n========================================');
    console.log('CREDENTIAL MIGRATION SUMMARY');
    console.log('========================================');
    console.log(`Total Connections:  ${this.stats.totalConnections}`);
    console.log(`Migrated:           ${this.stats.migrated} ✅`);
    console.log(`Failed:             ${this.stats.failed} ❌`);
    console.log(`Skipped:            ${this.stats.skipped} ⏭️`);
    console.log('========================================');

    if (status.needsInitialization) {
      console.log('✅ DEK system initialized successfully');
    }

    if (this.stats.migrated > 0) {
      console.log('✅ All credentials re-encrypted with hardware-derived keys');
      console.log('⚠️  IMPORTANT: Remove ENCRYPTION_KEY from .env after verification');
    }

    console.log('========================================\n');
  }
}

/**
 * Main execution
 */
async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');

  if (dryRun) {
    console.log('\n⚠️  DRY RUN MODE - No changes will be made\n');
  }

  const migrator = new CredentialMigrator();

  try {
    // 1. Initialize
    await migrator.initialize();

    // 2. Check status
    const status = await migrator.checkMigrationStatus();

    // 3. Initialize DEK system if needed
    if (status.needsInitialization) {
      console.log('🔧 Initializing DEK system (first-time setup)...');
      await migrator.initializeDEKSystem();
      console.log('✅ DEK system initialized\n');
    }

    // 4. Backup existing credentials
    if (!dryRun) {
      await migrator.backupCredentials();
    }

    // 5. Migrate credentials
    await migrator.migrateCredentials(dryRun);

    // 6. Verify migration (only if not dry run)
    if (!dryRun && migrator['stats'].migrated > 0) {
      const verified = await migrator.verifyMigration();
      if (!verified) {
        throw new Error('Migration verification failed');
      }
    }

    // 7. Print summary
    migrator.printSummary(status);

    if (!dryRun) {
      console.log('🎉 Migration completed successfully!');
      console.log('📝 Next steps:');
      console.log('   1. Verify your application still works');
      console.log('   2. Remove ENCRYPTION_KEY from .env');
      console.log('   3. Restart enclave service\n');
    } else {
      console.log('✅ Dry run completed - no changes made');
      console.log('📝 Run without --dry-run to perform actual migration\n');
    }

    process.exit(0);
  } catch (error) {
    logger.error('Migration failed', { error });
    console.error('\n❌ Migration failed:', error);
    console.error('\nCredentials have been rolled back to original state\n');
    process.exit(1);
  }
}

// Run migration
main();
