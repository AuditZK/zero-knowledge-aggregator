import * as crypto from 'node:crypto';
import { injectable } from 'tsyringe';
import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';

const logger = getLogger('E2EEncryption');

/** ECIES encryption (ECDH P-256 + AES-256-GCM) for credential protection against VPS MITM. */
@injectable()
export class E2EEncryptionService {
  private privateKey: crypto.KeyObject | null = null;
  private publicKeyPem: string | null = null;

  async initialize(): Promise<void> {
    logger.info('Generating ECDH key pair...');

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    this.privateKey = crypto.createPrivateKey(privateKey);
    this.publicKeyPem = publicKey;

    logger.info('ECDH key pair generated', {
      publicKeyFingerprint: this.getPublicKeyFingerprint().slice(0, 16) + '...',
    });
  }

  getPublicKey(): string {
    if (!this.publicKeyPem) throw new Error('E2E encryption not initialized');
    return this.publicKeyPem;
  }

  getPublicKeyFingerprint(): string {
    if (!this.publicKeyPem) throw new Error('E2E encryption not initialized');
    return crypto.createHash('sha256').update(this.publicKeyPem).digest('hex');
  }

  /** Decrypts ECIES payload. */
  decrypt(encryptedData: {
    ephemeralPublicKey: string;
    iv: string;
    ciphertext: string;
    tag: string;
  }): string {
    if (!this.privateKey) throw new Error('E2E encryption not initialized');

    try {
      const ephemeralPublicKey = crypto.createPublicKey(encryptedData.ephemeralPublicKey);
      const sharedSecret = crypto.diffieHellman({ privateKey: this.privateKey, publicKey: ephemeralPublicKey });
      const aesKey = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from('enclave-e2e-encryption'), 32);

      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(aesKey), Buffer.from(encryptedData.iv, 'hex'));
      decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));

      let decrypted = decipher.update(encryptedData.ciphertext, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      logger.info('Credentials decrypted', { size: decrypted.length });
      return decrypted;
    } catch (error: unknown) {
      logger.error('Decryption failed', { error: extractErrorMessage(error) });
      throw new Error('Failed to decrypt credentials');
    }
  }

  /** Encrypts data (for testing). */
  encrypt(plaintext: string): {
    ephemeralPublicKey: string;
    iv: string;
    ciphertext: string;
    tag: string;
  } {
    if (!this.publicKeyPem) {
      throw new Error('E2E encryption not initialized');
    }

    // Generate ephemeral key pair
    const { privateKey: ephemeralPrivateKey, publicKey: ephemeralPublicKey } =
      crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });

    // Perform ECDH
    const enclavePublicKey = crypto.createPublicKey(this.publicKeyPem);
    const sharedSecret = crypto.diffieHellman({
      privateKey: crypto.createPrivateKey(ephemeralPrivateKey),
      publicKey: enclavePublicKey
    });

    // Derive AES key
    const aesKey = crypto.hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.alloc(0),
      Buffer.from('enclave-e2e-encryption'),
      32
    );

    // Encrypt with AES-256-GCM
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(aesKey), iv);

    let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const tag = cipher.getAuthTag();

    return {
      ephemeralPublicKey: ephemeralPublicKey,
      iv: iv.toString('hex'),
      ciphertext,
      tag: tag.toString('hex')
    };
  }
}
