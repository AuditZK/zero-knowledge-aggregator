import * as crypto from 'crypto';

export class EncryptionService {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly KEY_LENGTH = 32;
  private static readonly IV_LENGTH = 16;
  private static readonly TAG_LENGTH = 16;

  private static getKey(): Buffer {
    const encryptionKey = process.env.ENCRYPTION_KEY;
    if (!encryptionKey) {
      throw new Error('ENCRYPTION_KEY environment variable is required');
    }

    // Use SHA-256 to derive a consistent 32-byte key from the env variable
    return crypto.createHash('sha256').update(encryptionKey).digest();
  }

  static encrypt(text: string): string {
    const key = this.getKey();
    const iv = crypto.randomBytes(this.IV_LENGTH);
    const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const tag = cipher.getAuthTag();

    // Combine iv + tag + encrypted data
    return iv.toString('hex') + tag.toString('hex') + encrypted;
  }

  static decrypt(encryptedData: string): string {
    const key = this.getKey();

    // Extract iv, tag, and encrypted data
    const iv = Buffer.from(encryptedData.slice(0, this.IV_LENGTH * 2), 'hex');
    const tag = Buffer.from(encryptedData.slice(this.IV_LENGTH * 2, (this.IV_LENGTH + this.TAG_LENGTH) * 2), 'hex');
    const encrypted = encryptedData.slice((this.IV_LENGTH + this.TAG_LENGTH) * 2);

    const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  static hash(text: string): string {
    return crypto.createHash('sha256').update(text).digest('hex');
  }

  static createCredentialsHash(apiKey: string, apiSecret: string, passphrase?: string): string {
    const credentialsString = `${apiKey}:${apiSecret}:${passphrase || ''}`;
    return this.hash(credentialsString);
  }
}