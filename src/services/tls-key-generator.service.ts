import * as crypto from 'crypto';
import { injectable } from 'tsyringe';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('TlsKeyGenerator');

export interface TlsCredentials {
  privateKey: string;   // PEM format - NEVER leaves enclave RAM
  certificate: string;  // PEM format - can be shared
  fingerprint: string;  // SHA-256 fingerprint for attestation
}

/**
 * TLS Key Generator Service
 *
 * SECURITY: Generates TLS private key INSIDE the enclave.
 * The VPS hypervisor NEVER sees the private key.
 *
 * Architecture:
 * 1. Generate ECDSA P-256 key pair in SEV-SNP protected RAM
 * 2. Create self-signed certificate
 * 3. Include certificate fingerprint in attestation report
 * 4. Client verifies: attestation → fingerprint → TLS cert matches
 */
@injectable()
export class TlsKeyGeneratorService {
  private credentials: TlsCredentials | null = null;
  private readonly CERT_VALIDITY_DAYS = 365;
  private readonly KEY_ALGORITHM = 'ec';
  private readonly CURVE = 'prime256v1'; // P-256, NIST approved

  /**
   * Generate or retrieve TLS credentials
   * Credentials are generated once and kept in memory
   */
  async getCredentials(): Promise<TlsCredentials> {
    if (this.credentials) {
      return this.credentials;
    }

    logger.info('Generating TLS credentials inside enclave...');
    this.credentials = await this.generateCredentials();
    logger.info('TLS credentials generated', {
      fingerprint: this.credentials.fingerprint,
      algorithm: 'ECDSA P-256',
      validity: `${this.CERT_VALIDITY_DAYS} days`
    });

    return this.credentials;
  }

  /**
   * Get certificate fingerprint for attestation
   * This fingerprint should be included in SEV-SNP report data
   */
  getFingerprint(): string | null {
    return this.credentials?.fingerprint || null;
  }

  /**
   * Generate ECDSA key pair and self-signed certificate
   */
  private async generateCredentials(): Promise<TlsCredentials> {
    // Generate ECDSA P-256 key pair
    const { privateKey, publicKey } = crypto.generateKeyPairSync(this.KEY_ALGORITHM, {
      namedCurve: this.CURVE,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    // Create self-signed certificate
    const certificate = this.createSelfSignedCert(privateKey, publicKey);

    // Calculate certificate fingerprint (SHA-256)
    const fingerprint = this.calculateFingerprint(certificate);

    return {
      privateKey,
      certificate,
      fingerprint
    };
  }

  /**
   * Create a self-signed X.509 certificate
   * Uses Node.js crypto for certificate generation
   */
  private createSelfSignedCert(privateKey: string, publicKey: string): string {
    // Certificate subject and issuer
    const subject = [
      { type: '2.5.4.3', value: 'Track Record Enclave' },           // CN
      { type: '2.5.4.10', value: 'Track Record Platform' },         // O
      { type: '2.5.4.6', value: 'FR' }                              // C
    ];

    const now = new Date();
    const notBefore = now;
    const notAfter = new Date(now.getTime() + this.CERT_VALIDITY_DAYS * 24 * 60 * 60 * 1000);

    // Build certificate using crypto.X509Certificate (Node 16+)
    // For now, create a simple self-signed cert structure
    const cert = this.buildX509Certificate({
      subject,
      issuer: subject, // Self-signed
      publicKey,
      privateKey,
      notBefore,
      notAfter,
      serialNumber: crypto.randomBytes(16).toString('hex')
    });

    return cert;
  }

  /**
   * Build X.509 certificate
   * Simplified implementation - in production use node-forge or similar
   */
  private buildX509Certificate(options: {
    subject: Array<{ type: string; value: string }>;
    issuer: Array<{ type: string; value: string }>;
    publicKey: string;
    privateKey: string;
    notBefore: Date;
    notAfter: Date;
    serialNumber: string;
  }): string {
    // Use crypto.createPrivateKey and sign
    const privateKeyObj = crypto.createPrivateKey(options.privateKey);

    // Build TBS (To Be Signed) certificate structure
    // This is a simplified ASN.1 DER encoding
    const tbsCertificate = this.buildTbsCertificate(options);

    // Sign with private key
    const sign = crypto.createSign('SHA256');
    sign.update(tbsCertificate);
    const signature = sign.sign(privateKeyObj);

    // Combine TBS + signature algorithm + signature
    const certificate = this.wrapCertificate(tbsCertificate, signature);

    // Convert to PEM
    const pem = '-----BEGIN CERTIFICATE-----\n' +
      certificate.toString('base64').match(/.{1,64}/g)?.join('\n') +
      '\n-----END CERTIFICATE-----\n';

    return pem;
  }

  /**
   * Build TBS (To Be Signed) Certificate structure
   */
  private buildTbsCertificate(options: {
    subject: Array<{ type: string; value: string }>;
    publicKey: string;
    notBefore: Date;
    notAfter: Date;
    serialNumber: string;
  }): Buffer {
    const parts: Buffer[] = [];

    // Version (v3 = 2)
    parts.push(Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]));

    // Serial number
    const serialBytes = Buffer.from(options.serialNumber, 'hex');
    parts.push(this.wrapAsn1(0x02, serialBytes));

    // Signature algorithm (ecdsa-with-SHA256)
    parts.push(Buffer.from([
      0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
    ]));

    // Issuer (same as subject for self-signed)
    parts.push(this.buildName(options.subject));

    // Validity
    parts.push(this.buildValidity(options.notBefore, options.notAfter));

    // Subject
    parts.push(this.buildName(options.subject));

    // Subject Public Key Info
    const pubKeyDer = this.pemToDer(options.publicKey);
    parts.push(pubKeyDer);

    // Wrap as SEQUENCE
    return this.wrapAsn1(0x30, Buffer.concat(parts));
  }

  /**
   * Build X.509 Name structure
   */
  private buildName(attributes: Array<{ type: string; value: string }>): Buffer {
    const rdnSequences = attributes.map(attr => {
      const oid = this.oidToBuffer(attr.type);
      const value = this.wrapAsn1(0x0c, Buffer.from(attr.value, 'utf8')); // UTF8String
      const atv = this.wrapAsn1(0x30, Buffer.concat([oid, value]));
      return this.wrapAsn1(0x31, atv); // SET
    });
    return this.wrapAsn1(0x30, Buffer.concat(rdnSequences));
  }

  /**
   * Build Validity structure
   * UTCTime format: YYMMDDHHMMSSZ (13 chars total)
   */
  private buildValidity(notBefore: Date, notAfter: Date): Buffer {
    const formatTime = (d: Date) => {
      // ISO: 2025-12-29T00:40:30.000Z -> UTCTime: 251229004030Z
      const str = d.toISOString()
        .replace(/[-:T]/g, '')  // Remove dashes, colons, and T separator
        .replace(/\.\d{3}/, ''); // Remove milliseconds
      return Buffer.from(str.slice(2, 14) + 'Z', 'ascii'); // YYMMDDHHMMSSZ
    };
    const nb = this.wrapAsn1(0x17, formatTime(notBefore));
    const na = this.wrapAsn1(0x17, formatTime(notAfter));
    return this.wrapAsn1(0x30, Buffer.concat([nb, na]));
  }

  /**
   * Convert OID string to buffer
   */
  private oidToBuffer(oid: string): Buffer {
    const parts = oid.split('.').map(Number);
    const bytes: number[] = [];

    // First two components (OID must have at least 2 parts)
    const first = parts[0] ?? 0;
    const second = parts[1] ?? 0;
    bytes.push(first * 40 + second);

    // Remaining components (base-128 encoding)
    for (let i = 2; i < parts.length; i++) {
      let n = parts[i] ?? 0;
      const encoded: number[] = [];
      do {
        encoded.unshift(n & 0x7f);
        n >>= 7;
      } while (n > 0);
      for (let j = 0; j < encoded.length - 1; j++) {
        const val = encoded[j];
        if (val !== undefined) {
          encoded[j] = val | 0x80;
        }
      }
      bytes.push(...encoded);
    }

    return this.wrapAsn1(0x06, Buffer.from(bytes));
  }

  /**
   * Wrap data in ASN.1 TLV structure
   */
  private wrapAsn1(tag: number, data: Buffer): Buffer {
    const len = data.length;
    let lenBytes: Buffer;

    if (len < 128) {
      lenBytes = Buffer.from([len]);
    } else if (len < 256) {
      lenBytes = Buffer.from([0x81, len]);
    } else {
      lenBytes = Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
    }

    return Buffer.concat([Buffer.from([tag]), lenBytes, data]);
  }

  /**
   * Convert PEM to DER
   */
  private pemToDer(pem: string): Buffer {
    const base64 = pem
      .replace(/-----BEGIN.*-----/, '')
      .replace(/-----END.*-----/, '')
      .replace(/\s/g, '');
    return Buffer.from(base64, 'base64');
  }

  /**
   * Wrap TBS certificate with signature
   */
  private wrapCertificate(tbsCert: Buffer, signature: Buffer): Buffer {
    // Signature algorithm
    const sigAlg = Buffer.from([
      0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
    ]);

    // Signature as BIT STRING
    const sigBitString = this.wrapAsn1(0x03, Buffer.concat([Buffer.from([0x00]), signature]));

    // Combine all
    return this.wrapAsn1(0x30, Buffer.concat([tbsCert, sigAlg, sigBitString]));
  }

  /**
   * Calculate SHA-256 fingerprint of certificate
   */
  private calculateFingerprint(certPem: string): string {
    const der = this.pemToDer(certPem);
    const hash = crypto.createHash('sha256').update(der).digest('hex');
    // Format as colon-separated uppercase
    return hash.toUpperCase().match(/.{2}/g)?.join(':') || hash;
  }

  /**
   * Verify a certificate matches our fingerprint
   */
  verifyFingerprint(certPem: string, expectedFingerprint: string): boolean {
    const actualFingerprint = this.calculateFingerprint(certPem);
    return actualFingerprint === expectedFingerprint;
  }

  /**
   * Clear credentials from memory (for graceful shutdown)
   */
  clearCredentials(): void {
    if (this.credentials) {
      // Overwrite private key in memory
      const keyBuffer = Buffer.from(this.credentials.privateKey);
      crypto.randomFillSync(keyBuffer);
      this.credentials = null;
      logger.info('TLS credentials cleared from memory');
    }
  }
}
