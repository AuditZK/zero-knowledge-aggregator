import * as crypto from 'node:crypto';
import { injectable, inject } from 'tsyringe';
import { KeyManagementService } from './key-management.service';
import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';

const logger = getLogger('EncryptionService');

/** AES-256-GCM encryption using hardware-derived keys (AMD SEV-SNP). */
@injectable()
export class EncryptionService {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly IV_LENGTH = 16;
  private static readonly TAG_LENGTH = 16;

  constructor(
    @inject(KeyManagementService) private readonly keyManagement: KeyManagementService
  ) {}

  private devKeyCache: Buffer | null = null;

  private async getKey(): Promise<Buffer> {
    try {
      const dek = await this.keyManagement.getCurrentDEK();
      logger.info('Retrieved encryption key from hardware-derived DEK');
      return dek;
    } catch (error: unknown) {
      // Dev fallback: use ENCRYPTION_KEY env var when SEV-SNP hardware unavailable
      if (process.env.NODE_ENV !== 'production' && process.env.ENCRYPTION_KEY) {
        if (!this.devKeyCache) {
          this.devKeyCache = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
          logger.warn('Using ENCRYPTION_KEY env var fallback (DEV ONLY — no hardware key)');
        }
        return this.devKeyCache;
      }

      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to get encryption key from hardware derivation', { error: errorMessage });
      throw new Error(`Cannot get encryption key - AMD SEV-SNP required: ${errorMessage}`);
    }
  }

  /** Encrypts text. Returns hex-encoded (iv + tag + ciphertext). */
  async encrypt(text: string): Promise<string> {
    try {
      const key = await this.getKey();
      const iv = crypto.randomBytes(EncryptionService.IV_LENGTH);
      const cipher = crypto.createCipheriv(EncryptionService.ALGORITHM, key, iv);

      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const tag = cipher.getAuthTag();

      const result = iv.toString('hex') + tag.toString('hex') + encrypted;
      logger.info('Data encrypted successfully', { dataLength: text.length });
      return result;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Encryption failed', { error: errorMessage });
      throw new Error(`Encryption failed: ${errorMessage}`);
    }
  }

  /** Decrypts hex-encoded data (iv + tag + ciphertext). */
  async decrypt(encryptedData: string): Promise<string> {
    try {
      const key = await this.getKey();

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

  hash(text: string): string {
    return crypto.createHash('sha256').update(text).digest('hex');
  }

  createCredentialsHash(apiKey: string, apiSecret: string, passphrase?: string): string {
    const credentialsString = `${apiKey}:${apiSecret}:${passphrase || ''}`;
    return this.hash(credentialsString);
  }

  async isHardwareKeyAvailable(): Promise<boolean> {
    return this.keyManagement.isSevSnpAvailable();
  }

  async getCurrentMasterKeyId(): Promise<string> {
    return this.keyManagement.getCurrentMasterKeyId();
  }
}
