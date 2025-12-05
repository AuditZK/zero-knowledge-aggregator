import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('DEKRepository');

export interface WrappedDEK {
  id: string;
  encryptedDEK: string;
  iv: string;
  authTag: string;
  keyVersion: string;
  masterKeyId: string;
  isActive: boolean;
  rotatedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Repository for Data Encryption Key (DEK) persistence
 *
 * SECURITY: This repository manages wrapped (encrypted) DEKs, not raw keys.
 * The actual DEK is only decrypted in-memory when needed.
 */
@injectable()
export class DEKRepository {
  constructor(
    @inject('PrismaClient') private prisma: PrismaClient
  ) {}

  /**
   * Gets the currently active DEK
   *
   * @returns Active wrapped DEK or null if none exists
   */
  async getActiveDEK(): Promise<WrappedDEK | null> {
    try {
      const dek = await this.prisma.dataEncryptionKey.findFirst({
        where: { isActive: true }
      });

      if (!dek) {
        logger.warn('No active DEK found in database');
        return null;
      }

      logger.info('Retrieved active DEK', {
        dekId: dek.id,
        keyVersion: dek.keyVersion,
        masterKeyId: dek.masterKeyId
      });

      return dek;
    } catch (error) {
      logger.error('Failed to retrieve active DEK', { error });
      throw error;
    }
  }

  /**
   * Creates a new DEK and stores it encrypted
   *
   * @param wrappedDEK Wrapped DEK data from KeyDerivationService
   * @returns Created DEK record
   */
  async createDEK(wrappedDEK: {
    encryptedDEK: string;
    iv: string;
    authTag: string;
    keyVersion: string;
    masterKeyId: string;
  }): Promise<WrappedDEK> {
    try {
      // Deactivate any existing active DEK (only one active at a time)
      await this.prisma.dataEncryptionKey.updateMany({
        where: { isActive: true },
        data: {
          isActive: false,
          rotatedAt: new Date()
        }
      });

      // Create new active DEK
      const dek = await this.prisma.dataEncryptionKey.create({
        data: {
          encryptedDEK: wrappedDEK.encryptedDEK,
          iv: wrappedDEK.iv,
          authTag: wrappedDEK.authTag,
          keyVersion: wrappedDEK.keyVersion,
          masterKeyId: wrappedDEK.masterKeyId,
          isActive: true
        }
      });

      logger.info('Created new active DEK', {
        dekId: dek.id,
        keyVersion: dek.keyVersion,
        masterKeyId: dek.masterKeyId
      });

      return dek;
    } catch (error) {
      logger.error('Failed to create DEK', { error });
      throw error;
    }
  }

  /**
   * Rotates the DEK by creating a new one and deactivating the old one
   *
   * @param newWrappedDEK New wrapped DEK data
   * @returns Newly created active DEK
   */
  async rotateDEK(newWrappedDEK: {
    encryptedDEK: string;
    iv: string;
    authTag: string;
    keyVersion: string;
    masterKeyId: string;
  }): Promise<WrappedDEK> {
    logger.info('Starting DEK rotation');
    return this.createDEK(newWrappedDEK); // createDEK already handles deactivation
  }

  /**
   * Gets all DEKs (active and inactive) for migration purposes
   *
   * @returns All DEK records
   */
  async getAllDEKs(): Promise<WrappedDEK[]> {
    try {
      const deks = await this.prisma.dataEncryptionKey.findMany({
        orderBy: { createdAt: 'desc' }
      });

      logger.info('Retrieved all DEKs', { count: deks.length });

      return deks;
    } catch (error) {
      logger.error('Failed to retrieve all DEKs', { error });
      throw error;
    }
  }

  /**
   * Finds DEKs by master key ID
   *
   * Useful for detecting which DEKs need re-wrapping after master key change
   *
   * @param masterKeyId Master key identifier
   * @returns DEKs wrapped with this master key
   */
  async getDEKsByMasterKeyId(masterKeyId: string): Promise<WrappedDEK[]> {
    try {
      const deks = await this.prisma.dataEncryptionKey.findMany({
        where: { masterKeyId },
        orderBy: { createdAt: 'desc' }
      });

      logger.info('Retrieved DEKs by master key ID', {
        masterKeyId,
        count: deks.length
      });

      return deks;
    } catch (error) {
      logger.error('Failed to retrieve DEKs by master key ID', { error });
      throw error;
    }
  }

  /**
   * Deletes inactive DEKs older than a specified date
   *
   * Used for cleanup after successful migration
   *
   * @param olderThan Delete DEKs rotated before this date
   * @returns Number of deleted records
   */
  async deleteInactiveDEKs(olderThan: Date): Promise<number> {
    try {
      const result = await this.prisma.dataEncryptionKey.deleteMany({
        where: {
          isActive: false,
          rotatedAt: {
            lt: olderThan
          }
        }
      });

      logger.info('Deleted inactive DEKs', {
        count: result.count,
        olderThan: olderThan.toISOString()
      });

      return result.count;
    } catch (error) {
      logger.error('Failed to delete inactive DEKs', { error });
      throw error;
    }
  }

  /**
   * Checks if any active DEK exists
   *
   * @returns true if active DEK exists, false otherwise
   */
  async hasActiveDEK(): Promise<boolean> {
    try {
      const count = await this.prisma.dataEncryptionKey.count({
        where: { isActive: true }
      });

      return count > 0;
    } catch (error) {
      logger.error('Failed to check for active DEK', { error });
      throw error;
    }
  }
}
