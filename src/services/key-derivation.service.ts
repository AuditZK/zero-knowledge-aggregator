import * as crypto from 'crypto';
import { injectable, inject } from 'tsyringe';
import { SevSnpAttestationService } from './sev-snp-attestation.service';
import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';

const logger = getLogger('KeyDerivation');

/**
 * Derives master key from AMD SEV-SNP measurement, wraps/unwraps DEKs.
 * Key hierarchy: Hardware Measurement -> Master Key (HKDF) -> Wrapped DEKs -> Credentials
 */
@injectable()
export class KeyDerivationService {
  private readonly KEY_VERSION = 'v1';
  private readonly HKDF_INFO = 'track-record-enclave-dek';
  private readonly KEY_LENGTH = 32;

  constructor(
    @inject(SevSnpAttestationService) private attestationService: SevSnpAttestationService
  ) { }

  /** Derives master key from SEV-SNP measurement using HKDF-SHA256. */
  async deriveMasterKey(): Promise<Buffer> {
    try {
      const attestationResult = await this.attestationService.getAttestationReport();

      if (!attestationResult.verified || !attestationResult.measurement) {
        throw new Error('SEV-SNP attestation verification failed - cannot derive key');
      }

      const measurementBuffer = Buffer.from(attestationResult.measurement, 'hex');

      logger.info('Deriving master key from SEV-SNP measurement', {
        keyVersion: this.KEY_VERSION,
        measurementLength: measurementBuffer.length,
        platformVersion: attestationResult.platformVersion
      });

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

  /** Generates a random 256-bit DEK. */
  generateDataEncryptionKey(): Buffer {
    const dek = crypto.randomBytes(this.KEY_LENGTH);
    logger.info('Generated new random DEK', { length: dek.length });
    return dek;
  }

  /** Wraps DEK with master key using AES-256-GCM. */
  wrapKey(dek: Buffer, masterKey: Buffer): {
    encryptedDEK: string;
    iv: string;
    authTag: string;
    keyVersion: string;
  } {
    try {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);

      const encryptedDEK = Buffer.concat([cipher.update(dek), cipher.final()]);
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

  /** Unwraps DEK using master key. Throws if tampered. */
  unwrapKey(
    wrappedDEK: { encryptedDEK: string; iv: string; authTag: string; keyVersion: string },
    masterKey: Buffer
  ): Buffer {
    try {
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

      const dek = Buffer.concat([decipher.update(encryptedDEK), decipher.final()]);
      logger.info('DEK unwrapped successfully', { keyVersion: wrappedDEK.keyVersion });
      return dek;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to unwrap DEK - possible tampering or wrong master key', { error: errorMessage });
      throw new Error(`Key unwrapping failed: ${errorMessage}`);
    }
  }

  /** Returns first 64 bits of SHA-256(masterKey) as hex identifier. */
  getMasterKeyId(masterKey: Buffer): string {
    const hash = crypto.createHash('sha256').update(masterKey).digest();
    return hash.subarray(0, 8).toString('hex');
  }

  async isSevSnpAvailable(): Promise<boolean> {
    try {
      const attestationResult = await this.attestationService.getAttestationReport();
      return attestationResult.verified && attestationResult.sevSnpEnabled;
    } catch {
      return false;
    }
  }
}
