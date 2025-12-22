import * as crypto from 'crypto';
import { injectable } from 'tsyringe';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('E2EEncryption');

/**
 * End-to-End Encryption Service
 *
 * Provides application-level encryption for credentials submitted to the enclave.
 * This adds a second layer of encryption on top of TLS, ensuring that even if
 * the VPS performs a MITM attack on the TLS connection, credentials remain encrypted.
 *
 * Uses ECIES (Elliptic Curve Integrated Encryption Scheme) with:
 * - ECDH for key agreement (P-256 curve)
 * - AES-256-GCM for symmetric encryption
 * - SHA-256 for KDF
 */
@injectable()
export class E2EEncryptionService {
  private privateKey: crypto.KeyObject | null = null;
  private publicKeyPem: string | null = null;

  /**
   * Generate ECDH key pair for E2E encryption
   * Private key stored ONLY in enclave RAM, never exposed
   */
  async initialize(): Promise<void> {
    logger.info('[E2E] Generating ECDH key pair for end-to-end encryption...');

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1', // P-256 (widely supported, secure)
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    this.privateKey = crypto.createPrivateKey(privateKey);
    this.publicKeyPem = publicKey;

    // Calculate fingerprint for logging
    const publicKeyHash = crypto.createHash('sha256')
      .update(publicKey)
      .digest('hex');

    logger.info('[E2E] ECDH key pair generated', {
      curve: 'prime256v1',
      publicKeyFingerprint: publicKeyHash.slice(0, 16) + '...',
      storage: 'Private key in RAM only, never written to disk'
    });
  }

  /**
   * Get the public key for client-side encryption
   */
  getPublicKey(): string {
    if (!this.publicKeyPem) {
      throw new Error('E2E encryption not initialized');
    }
    return this.publicKeyPem;
  }

  /**
   * Get public key fingerprint for attestation binding
   */
  getPublicKeyFingerprint(): string {
    if (!this.publicKeyPem) {
      throw new Error('E2E encryption not initialized');
    }
    return crypto.createHash('sha256')
      .update(this.publicKeyPem)
      .digest('hex');
  }

  /**
   * Decrypt credentials encrypted by the client
   *
   * Expected format (from client):
   * {
   *   ephemeralPublicKey: string (PEM),
   *   iv: string (hex),
   *   ciphertext: string (hex),
   *   tag: string (hex)
   * }
   */
  decrypt(encryptedData: {
    ephemeralPublicKey: string;
    iv: string;
    ciphertext: string;
    tag: string;
  }): string {
    if (!this.privateKey) {
      throw new Error('E2E encryption not initialized');
    }

    try {
      // 1. Parse ephemeral public key from client
      const ephemeralPublicKey = crypto.createPublicKey(encryptedData.ephemeralPublicKey);

      // 2. Perform ECDH to derive shared secret
      const sharedSecret = crypto.diffieHellman({
        privateKey: this.privateKey,
        publicKey: ephemeralPublicKey
      });

      // 3. Derive AES key from shared secret using HKDF
      const aesKey = crypto.hkdfSync(
        'sha256',
        sharedSecret,
        Buffer.alloc(0), // no salt
        Buffer.from('enclave-e2e-encryption'), // info
        32 // 256 bits for AES-256
      );

      // 4. Decrypt with AES-256-GCM
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        Buffer.from(aesKey),
        Buffer.from(encryptedData.iv, 'hex')
      );

      decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));

      let decrypted = decipher.update(encryptedData.ciphertext, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      logger.info('[E2E] Credentials decrypted successfully', {
        size: decrypted.length,
        security: 'End-to-end encrypted, VPS cannot read even with TLS MITM'
      });

      return decrypted;
    } catch (error: any) {
      logger.error('[E2E] Decryption failed', { error: error.message });
      throw new Error('Failed to decrypt credentials: Invalid encryption or corrupted data');
    }
  }

  /**
   * Encrypt data (for testing purposes)
   * In production, only clients encrypt, enclave only decrypts
   */
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
