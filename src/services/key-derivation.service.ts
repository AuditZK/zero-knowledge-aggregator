import * as crypto from 'crypto';
import { injectable, inject } from 'tsyringe';
import { SevSnpAttestationService } from './sev-snp-attestation.service';
import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';

const logger = getLogger('KeyDerivation');

/**
 * AMD SEV-SNP Hardware-Based Key Derivation Service
 *
 * SECURITY ARCHITECTURE:
 * - Derives master encryption key from AMD SEV-SNP measurement (hardware-based)
 * - Master key changes automatically when enclave code is updated
 * - Data Encryption Keys (DEKs) are randomly generated and wrapped with master key
 * - No secrets stored in environment variables
 * - Zero cost, enterprise-level security
 *
 * KEY HIERARCHY:
 * 1. AMD Hardware → Measurement (SHA-384 hash of enclave code)
 * 2. Measurement → Master Key (via HKDF)
 * 3. Master Key → Wrapped DEKs (stored in database)
 * 4. DEKs → Encrypt/decrypt user credentials
 */
@injectable()
export class KeyDerivationService {
  private readonly KEY_VERSION = 'v1';
  private readonly HKDF_INFO = 'track-record-enclave-dek';
  private readonly KEY_LENGTH = 32; // 256 bits for AES-256

  constructor(
    @inject(SevSnpAttestationService) private attestationService: SevSnpAttestationService
  ) { }

  /**
   * Derives master encryption key from AMD SEV-SNP hardware measurement
   *
   * CRITICAL SECURITY PROPERTIES:
   * - Key is deterministic (same code = same key)
   * - Key changes on code update (forces DEK rotation)
   * - Never stored anywhere (derived on-demand from hardware)
   * - Unique per enclave build
   *
   * @returns 32-byte master encryption key
   * @throws Error if SEV-SNP attestation fails or not available
   */
  async deriveMasterKey(): Promise<Buffer> {
    try {
      // Get attestation report from AMD hardware
      const attestationResult = await this.attestationService.getAttestationReport();

      if (!attestationResult.verified || !attestationResult.measurement) {
        throw new Error('SEV-SNP attestation verification failed - cannot derive key');
      }

      // Extract measurement (SHA-384 hash of enclave code)
      const measurementHex = attestationResult.measurement;
      const measurementBuffer = Buffer.from(measurementHex, 'hex');

      logger.info('Deriving master key from SEV-SNP measurement', {
        keyVersion: this.KEY_VERSION,
        measurementLength: measurementBuffer.length,
        platformVersion: attestationResult.platformVersion
      });

      // Derive master key using HKDF-SHA256
      // IKM (Input Key Material) = AMD measurement
      // Salt = Platform version (optional, provides additional entropy)
      // Info = Application-specific context string
      const salt = attestationResult.platformVersion
        ? Buffer.from(attestationResult.platformVersion, 'utf8')
        : Buffer.alloc(0);

      const masterKey = crypto.hkdfSync(
        'sha256',
        measurementBuffer,
        salt,
        Buffer.from(this.HKDF_INFO, 'utf8'),
        this.KEY_LENGTH
      );

      logger.info('Master key derived successfully from hardware measurement');

      return Buffer.from(masterKey);
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to derive master key from SEV-SNP measurement', { error: errorMessage });
      throw new Error(`Key derivation failed: ${errorMessage}`);
    }
  }

  /**
   * Generates a new random Data Encryption Key (DEK)
   *
   * DEKs are used to encrypt user credentials. They are:
   * - Randomly generated (not derived from anything)
   * - Wrapped (encrypted) with the master key
   * - Stored encrypted in the database
   * - Unwrapped on-demand for credential encryption/decryption
   *
   * @returns 32-byte random DEK
   */
  generateDataEncryptionKey(): Buffer {
    const dek = crypto.randomBytes(this.KEY_LENGTH);
    logger.info('Generated new random DEK', { length: dek.length });
    return dek;
  }

  /**
   * Wraps (encrypts) a Data Encryption Key with the master key
   *
   * Uses AES-256-GCM for authenticated encryption:
   * - Confidentiality: DEK cannot be read without master key
   * - Integrity: Tampering is detectable
   * - Authenticity: Only this enclave can unwrap
   *
   * @param dek Data Encryption Key to wrap
   * @param masterKey Master key (derived from SEV-SNP measurement)
   * @returns Wrapped DEK with IV and auth tag
   */
  wrapKey(dek: Buffer, masterKey: Buffer): {
    encryptedDEK: string;
    iv: string;
    authTag: string;
    keyVersion: string;
  } {
    try {
      const iv = crypto.randomBytes(12); // 96-bit IV for GCM
      const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);

      const encryptedDEK = Buffer.concat([
        cipher.update(dek),
        cipher.final()
      ]);

      const authTag = cipher.getAuthTag();

      logger.info('DEK wrapped successfully', {
        keyVersion: this.KEY_VERSION,
        ivLength: iv.length,
        authTagLength: authTag.length
      });

      return {
        encryptedDEK: encryptedDEK.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        keyVersion: this.KEY_VERSION
      };
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to wrap DEK', { error: errorMessage });
      throw new Error(`Key wrapping failed: ${errorMessage}`);
    }
  }

  /**
   * Unwraps (decrypts) a Data Encryption Key using the master key
   *
   * Verifies integrity using GCM auth tag - if DEK was tampered with,
   * this will throw an error (preventing use of corrupted keys).
   *
   * @param wrappedDEK Wrapped DEK object from database
   * @param masterKey Master key (derived from SEV-SNP measurement)
   * @returns Decrypted DEK ready for use
   * @throws Error if authentication fails (tampered data)
   */
  unwrapKey(
    wrappedDEK: {
      encryptedDEK: string;
      iv: string;
      authTag: string;
      keyVersion: string;
    },
    masterKey: Buffer
  ): Buffer {
    try {
      // Verify key version compatibility
      if (wrappedDEK.keyVersion !== this.KEY_VERSION) {
        logger.warn('Key version mismatch - may require migration', {
          storedVersion: wrappedDEK.keyVersion,
          currentVersion: this.KEY_VERSION
        });
      }

      const iv = Buffer.from(wrappedDEK.iv, 'base64');
      const encryptedDEK = Buffer.from(wrappedDEK.encryptedDEK, 'base64');
      const authTag = Buffer.from(wrappedDEK.authTag, 'base64');

      const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
      decipher.setAuthTag(authTag);

      const dek = Buffer.concat([
        decipher.update(encryptedDEK),
        decipher.final()
      ]);

      logger.info('DEK unwrapped successfully', { keyVersion: wrappedDEK.keyVersion });

      return dek;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to unwrap DEK - possible tampering or wrong master key', {
        error: errorMessage
      });
      throw new Error(`Key unwrapping failed: ${errorMessage}`);
    }
  }

  /**
   * Derives a key identifier from the master key for storage reference
   *
   * This is NOT the key itself - it's a non-reversible hash used to:
   * - Identify which master key version wrapped a DEK
   * - Detect master key changes (code updates)
   * - Never reveals the actual key material
   *
   * @param masterKey Master key
   * @returns 16-character hex identifier
   */
  getMasterKeyId(masterKey: Buffer): string {
    const hash = crypto.createHash('sha256').update(masterKey).digest();
    return hash.subarray(0, 8).toString('hex'); // First 64 bits as hex
  }

  /**
   * Checks if SEV-SNP key derivation is available on this system
   *
   * @returns true if SEV-SNP hardware is available, false otherwise
   */
  async isSevSnpAvailable(): Promise<boolean> {
    try {
      const attestationResult = await this.attestationService.getAttestationReport();
      return attestationResult.verified && attestationResult.sevSnpEnabled;
    } catch {
      return false;
    }
  }
}
