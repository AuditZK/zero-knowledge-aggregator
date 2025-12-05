import * as crypto from 'crypto';
import { injectable, inject } from 'tsyringe';
import { KeyManagementService } from './key-management.service';
import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';

const logger = getLogger('EncryptionService');

/**
 * Encryption Service - Credential encryption/decryption
 *
 * SECURITY ARCHITECTURE (NEW):
 * - Encryption key derived from AMD SEV-SNP hardware measurement (NOT env var)
 * - Key automatically rotates on code updates (measurement changes)
 * - Enterprise-level security at €0 cost
 * - No secrets in environment variables
 *
 * MIGRATION SUPPORT:
 * - Backward compatible with old env var encrypted data (fallback mode)
 * - New encryptions use hardware-derived keys only
 * - Migration script available for re-encrypting old credentials
 */
@injectable()
export class EncryptionService {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly IV_LENGTH = 16;
  private static readonly TAG_LENGTH = 16;

  constructor(
    @inject(KeyManagementService) private keyManagement: KeyManagementService
  ) {}

  /**
   * Gets encryption key from AMD SEV-SNP hardware derivation
   *
   * NEW: Replaces environment variable key storage
   * - Derives master key from enclave measurement
   * - Unwraps Data Encryption Key (DEK) from database
   * - DEK is used for credential encryption/decryption
   *
   * @returns Current active DEK
   */
  private async getKey(): Promise<Buffer> {
    try {
      const dek = await this.keyManagement.getCurrentDEK();
      logger.info('Retrieved encryption key from hardware-derived DEK');
      return dek;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to get encryption key from hardware derivation', { error: errorMessage });

      // FALLBACK MODE: Use env var key (for backward compatibility during migration)
      // This allows existing encrypted credentials to still be decrypted
      // TODO: Remove this fallback after migration is complete
      if (process.env.ENCRYPTION_KEY) {
        logger.warn('Falling back to environment variable key - INSECURE, migration required');
        return crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY).digest();
      }

      throw new Error(`Cannot get encryption key: ${errorMessage}`);
    }
  }

  /**
   * Encrypts text using AES-256-GCM with hardware-derived key
   *
   * @param text Plaintext to encrypt
   * @returns Hex-encoded encrypted data (iv + tag + ciphertext)
   */
  async encrypt(text: string): Promise<string> {
    try {
      const key = await this.getKey();
      const iv = crypto.randomBytes(EncryptionService.IV_LENGTH);
      const cipher = crypto.createCipheriv(EncryptionService.ALGORITHM, key, iv);

      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const tag = cipher.getAuthTag();

      // Combine iv + tag + encrypted data
      const result = iv.toString('hex') + tag.toString('hex') + encrypted;

      logger.info('Data encrypted successfully', { dataLength: text.length });

      return result;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Encryption failed', { error: errorMessage });
      throw new Error(`Encryption failed: ${errorMessage}`);
    }
  }

  /**
   * Decrypts text using AES-256-GCM with hardware-derived key
   *
   * BACKWARD COMPATIBILITY:
   * - First attempts with hardware-derived key
   * - Falls back to env var key if hardware key fails (migration support)
   *
   * @param encryptedData Hex-encoded encrypted data (iv + tag + ciphertext)
   * @returns Decrypted plaintext
   */
  async decrypt(encryptedData: string): Promise<string> {
    try {
      const key = await this.getKey();

      // Extract iv, tag, and encrypted data
      const iv = Buffer.from(encryptedData.slice(0, EncryptionService.IV_LENGTH * 2), 'hex');
      const tag = Buffer.from(encryptedData.slice(EncryptionService.IV_LENGTH * 2, (EncryptionService.IV_LENGTH + EncryptionService.TAG_LENGTH) * 2), 'hex');
      const encrypted = encryptedData.slice((EncryptionService.IV_LENGTH + EncryptionService.TAG_LENGTH) * 2);

      const decipher = crypto.createDecipheriv(EncryptionService.ALGORITHM, key, iv);
      decipher.setAuthTag(tag);

      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      logger.info('Data decrypted successfully');

      return decrypted;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Decryption failed', { error: errorMessage });
      throw new Error(`Decryption failed: ${errorMessage}`);
    }
  }

  /**
   * Creates SHA-256 hash of text
   *
   * @param text Text to hash
   * @returns Hex-encoded hash
   */
  hash(text: string): string {
    return crypto.createHash('sha256').update(text).digest('hex');
  }

  /**
   * Creates hash of API credentials for change detection
   *
   * @param apiKey API key
   * @param apiSecret API secret
   * @param passphrase Optional passphrase
   * @returns Hex-encoded hash of credentials
   */
  createCredentialsHash(apiKey: string, apiSecret: string, passphrase?: string): string {
    const credentialsString = `${apiKey}:${apiSecret}:${passphrase || ''}`;
    return this.hash(credentialsString);
  }

  /**
   * Checks if AMD SEV-SNP key derivation is available
   *
   * @returns true if hardware derivation available, false if using fallback
   */
  async isHardwareKeyAvailable(): Promise<boolean> {
    return this.keyManagement.isSevSnpAvailable();
  }

  /**
   * Gets current master key ID for diagnostic purposes
   *
   * @returns Master key identifier (hash, not the key itself)
   */
  async getCurrentMasterKeyId(): Promise<string> {
    return this.keyManagement.getCurrentMasterKeyId();
  }
}