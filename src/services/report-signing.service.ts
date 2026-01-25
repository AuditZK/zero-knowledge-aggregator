import { injectable, inject } from 'tsyringe';
import { createHash, createSign, createVerify, generateKeyPairSync, KeyObject } from 'node:crypto';
import { getLogger } from '../utils/secure-enclave-logger';
import { SevSnpAttestationService } from './sev-snp-attestation.service';
import {
  SignedFinancialData,
  DisplayParameters,
  SignedReport,
  VerifySignatureRequest,
  VerifySignatureResponse
} from '../types/report.types';

const logger = getLogger('ReportSigning');

/**
 * Report Signing Service
 *
 * SECURITY: Generates ECDSA key pair at startup and signs reports.
 * The public key is included in each signed report for verification.
 *
 * Key properties:
 * - Key pair generated fresh at each enclave startup (ephemeral)
 * - Public key included in signed reports for external verification
 * - Private key never leaves enclave memory
 * - Uses ECDSA P-256 (secp256r1) with SHA-256
 */
@injectable()
export class ReportSigningService {
  private readonly privateKey: KeyObject;
  private readonly publicKeyBase64: string;
  private readonly algorithm = 'ECDSA-P256-SHA256';
  private cachedMeasurement: string | null = null;

  constructor(
    @inject(SevSnpAttestationService) private readonly attestationService: SevSnpAttestationService
  ) {
    // Generate ephemeral key pair at startup
    const keyPair = generateKeyPairSync('ec', {
      namedCurve: 'P-256'
    });

    this.privateKey = keyPair.privateKey;

    // Export public key to base64 for inclusion in reports
    this.publicKeyBase64 = keyPair.publicKey.export({
      type: 'spki',
      format: 'der'
    }).toString('base64');

    logger.info('Report signing service initialized', {
      algorithm: this.algorithm,
      publicKeyFingerprint: this.getPublicKeyFingerprint()
    });

    // Fetch and cache measurement at startup (async, non-blocking)
    this.fetchAndCacheMeasurement();
  }

  /**
   * Fetch SEV-SNP measurement and cache it
   * This runs at startup and caches the result for all reports
   */
  private async fetchAndCacheMeasurement(): Promise<void> {
    try {
      const attestation = await this.attestationService.getAttestationReport();
      if (attestation.measurement) {
        this.cachedMeasurement = attestation.measurement;
        logger.info('SEV-SNP measurement cached for report signing', {
          measurementPrefix: attestation.measurement.substring(0, 32) + '...'
        });
      }
    } catch (error) {
      logger.warn('Could not fetch SEV-SNP measurement (non-critical)', {
        error: error instanceof Error ? error.message : 'Unknown'
      });
    }
  }

  /**
   * Sign financial data with the enclave's private key
   *
   * SECURITY: Only SignedFinancialData is signed. DisplayParameters are NOT
   * part of the signature. This ensures:
   * 1. Same period = same signature (deduplication works)
   * 2. Users can customize presentation without invalidating the cryptographic proof
   * 3. The signature proves the NUMBERS are authentic, not arbitrary text labels
   */
  signFinancialData(financialData: SignedFinancialData, displayParams: DisplayParameters): SignedReport {
    // Serialize ONLY financial data deterministically (NOT display params)
    const financialJson = this.serializeFinancialData(financialData);

    // Calculate SHA-256 hash of the FINANCIAL DATA only
    const reportHash = createHash('sha256')
      .update(financialJson)
      .digest('hex');

    // Sign the hash with ECDSA (sign the hex hash string for external verification)
    const sign = createSign('SHA256');
    sign.update(reportHash);  // Sign hash, not JSON - allows verification with hash only
    sign.end();

    const signature = sign.sign(this.privateKey, 'base64');

    // Get enclave attestation info
    const isProduction = process.env.ENCLAVE_MODE === 'true';
    const attestationId = process.env.ATTESTATION_ID;

    const signedReport: SignedReport = {
      financialData,
      displayParams,
      signature,
      publicKey: this.publicKeyBase64,
      signatureAlgorithm: this.algorithm,
      enclaveVersion: process.env.ENCLAVE_VERSION || '1.0.0',
      attestationId: attestationId || undefined,
      enclaveMode: isProduction ? 'production' : 'development',
      measurement: this.cachedMeasurement || undefined,
      reportHash
    };

    logger.info('Financial data signed successfully', {
      reportId: financialData.reportId,
      reportHash: reportHash.substring(0, 16) + '...',
      signatureLength: signature.length,
      enclaveMode: signedReport.enclaveMode,
      displayParams: { reportName: displayParams.reportName }
    });

    return signedReport;
  }

  /**
   * Verify a report signature
   * Can verify reports signed by this enclave instance or any other
   * (as long as the public key is provided)
   */
  verifySignature(request: VerifySignatureRequest): VerifySignatureResponse {
    try {
      // Import the public key from base64
      const publicKeyDer = Buffer.from(request.publicKey, 'base64');

      // Reconstruct the data that was signed
      // Note: For external verification, the original report JSON is needed
      // This method is primarily for verifying signatures we created

      const verify = createVerify('SHA256');

      // For hash-based verification, we need the original data
      // This is a simplified version that verifies the hash
      verify.update(request.reportHash);
      verify.end();

      // Try to verify with provided public key
      const isValid = verify.verify(
        {
          key: publicKeyDer,
          format: 'der',
          type: 'spki'
        },
        request.signature,
        'base64'
      );

      return {
        valid: isValid
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown verification error';
      logger.error('Signature verification failed', { error: errorMessage });

      return {
        valid: false,
        error: errorMessage
      };
    }
  }

  /**
   * Verify a complete signed report
   *
   * SECURITY: Verifies only the financial data hash and signature.
   * Display parameters are NOT verified (they can be customized per request).
   */
  verifySignedReport(signedReport: SignedReport): VerifySignatureResponse {
    try {
      // Re-serialize the FINANCIAL DATA only (NOT display params)
      const financialJson = this.serializeFinancialData(signedReport.financialData);

      // Verify the hash matches
      const calculatedHash = createHash('sha256')
        .update(financialJson)
        .digest('hex');

      if (calculatedHash !== signedReport.reportHash) {
        return {
          valid: false,
          error: 'Financial data hash mismatch - data may have been tampered with'
        };
      }

      // Import the public key
      const publicKeyDer = Buffer.from(signedReport.publicKey, 'base64');

      // Verify signature (signature is on the hash, not the JSON)
      const verify = createVerify('SHA256');
      verify.update(signedReport.reportHash);
      verify.end();

      const isValid = verify.verify(
        {
          key: publicKeyDer,
          format: 'der',
          type: 'spki'
        },
        signedReport.signature,
        'base64'
      );

      if (!isValid) {
        return {
          valid: false,
          error: 'Invalid signature'
        };
      }

      return { valid: true };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown verification error';
      logger.error('Signed report verification failed', { error: errorMessage });

      return {
        valid: false,
        error: errorMessage
      };
    }
  }

  /**
   * Get the public key in base64 format
   */
  getPublicKey(): string {
    return this.publicKeyBase64;
  }

  /**
   * Get a fingerprint of the public key for logging
   */
  getPublicKeyFingerprint(): string {
    const hash = createHash('sha256')
      .update(this.publicKeyBase64)
      .digest('hex');
    return hash.substring(0, 16);
  }

  /**
   * Serialize financial data deterministically for signing
   * Uses sorted keys to ensure consistent serialization
   *
   * SECURITY: Only financial data is serialized - display params are excluded
   */
  private serializeFinancialData(financialData: SignedFinancialData): string {
    return JSON.stringify(financialData, this.sortedReplacer);
  }

  /**
   * JSON replacer that sorts object keys for deterministic serialization
   */
  private sortedReplacer(_key: string, value: unknown): unknown {
    if (value instanceof Date) {
      return value.toISOString();
    }
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      return Object.keys(value as Record<string, unknown>)
        .sort((a, b) => a.localeCompare(b))
        .reduce((sorted: Record<string, unknown>, key: string) => {
          sorted[key] = (value as Record<string, unknown>)[key];
          return sorted;
        }, {});
    }
    return value;
  }
}
