import express from 'express';
import * as https from 'https';
import * as fs from 'fs';
import { container } from 'tsyringe';
import { EnclaveWorker } from './enclave-worker';
import { CreateUserConnectionRequestSchema } from './validation/grpc-schemas';
import { getLogger } from './utils/secure-enclave-logger';
import { TlsKeyGeneratorService } from './services/tls-key-generator.service';
import { SevSnpAttestationService } from './services/sev-snp-attestation.service';
import { E2EEncryptionService } from './services/e2e-encryption.service';

const logger = getLogger('REST-Server');
const app = express();

// Middleware
app.use(express.json());

// Health check endpoint
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'enclave-rest', tls: true });
});

// Get TLS certificate fingerprint (for client verification)
app.get('/api/v1/tls/fingerprint', (_req, res) => {
  try {
    const tlsService = container.resolve(TlsKeyGeneratorService);
    const fingerprint = tlsService.getFingerprint();

    if (!fingerprint) {
      return res.status(503).json({
        error: 'TLS not initialized'
      });
    }

    return res.json({
      fingerprint,
      algorithm: 'SHA-256',
      usage: 'Compare with attestation report to verify TLS cert authenticity'
    });
  } catch (error: any) {
    return res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/v1/attestation
 * Get SEV-SNP attestation report with TLS fingerprint binding + E2E public key
 *
 * SECURITY: The reportData field contains SHA-256(TLS certificate).
 * The response also includes the E2E encryption public key for client-side encryption.
 *
 * Client verification flow:
 * 1. Fetch this attestation report
 * 2. Verify SEV-SNP signature (proves it's from genuine AMD hardware)
 * 3. Extract reportData from attestation
 * 4. Compare with SHA-256 of TLS certificate received during handshake
 * 5. If match: TLS connection is to the attested enclave (no MITM possible)
 * 6. Use e2ePublicKey to encrypt credentials before sending
 */
app.get('/api/v1/attestation', async (_req, res) => {
  try {
    const attestationService = container.resolve(SevSnpAttestationService);
    const tlsService = container.resolve(TlsKeyGeneratorService);
    const e2eService = container.resolve(E2EEncryptionService);

    const attestation = await attestationService.getAttestationReport();
    const fingerprint = tlsService.getFingerprint();
    const e2ePublicKey = e2eService.getPublicKey();
    const e2ePublicKeyFingerprint = e2eService.getPublicKeyFingerprint();

    return res.json({
      attestation: {
        verified: attestation.verified,
        sevSnpEnabled: attestation.sevSnpEnabled,
        vcekVerified: attestation.vcekVerified,
        measurement: attestation.measurement,
        reportData: attestation.reportData,
        platformVersion: attestation.platformVersion
      },
      tlsBinding: {
        fingerprint,
        algorithm: 'SHA-256',
        bound: attestation.reportData !== null,
        verification: 'reportData should equal SHA-256(TLS certificate)'
      },
      e2eEncryption: {
        publicKey: e2ePublicKey,
        publicKeyFingerprint: e2ePublicKeyFingerprint,
        algorithm: 'ECIES (ECDH P-256 + AES-256-GCM)',
        usage: 'Encrypt credentials with this key before sending for maximum security'
      },
      security: {
        tlsMitmProtection: attestation.reportData !== null,
        e2eMitmProtection: true,
        message: attestation.reportData
          ? 'Double encryption: TLS for transport + E2E for application layer'
          : 'WARNING: TLS fingerprint not bound - MITM possible'
      }
    });
  } catch (error: any) {
    logger.error('[REST] Attestation request failed:', error);
    return res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/v1/credentials/connect
 * Submit credentials to the enclave
 *
 * Supports TWO modes:
 *
 * 1. PLAINTEXT MODE (backward compatible, protected by TLS only):
 * {
 *   "user_uid": "...",
 *   "exchange": "binance",
 *   "api_key": "...",
 *   "api_secret": "...",
 *   "passphrase": "..." (optional)
 * }
 *
 * 2. E2E ENCRYPTED MODE (maximum security, protected by TLS + E2E):
 * {
 *   "user_uid": "...",
 *   "exchange": "binance",
 *   "encrypted": {
 *     "ephemeralPublicKey": "-----BEGIN PUBLIC KEY-----...",
 *     "iv": "hex...",
 *     "ciphertext": "hex...",
 *     "tag": "hex..."
 *   }
 * }
 *
 * E2E mode encrypts credentials client-side with enclave's public key,
 * making VPS MITM attacks impossible even if TLS is compromised.
 */
app.post('/api/v1/credentials/connect', async (req, res) => {
  try {
    let apiKey: string;
    let apiSecret: string;
    let passphrase: string | undefined;

    // Check if request uses E2E encryption
    if (req.body.encrypted) {
      logger.info('[REST] Processing E2E encrypted credential submission', {
        user_uid: req.body.user_uid,
        exchange: req.body.exchange,
        security: 'E2E encrypted - VPS MITM impossible'
      });

      // Decrypt credentials
      const e2eService = container.resolve(E2EEncryptionService);
      const decryptedJson = e2eService.decrypt(req.body.encrypted);
      const decryptedData = JSON.parse(decryptedJson);

      apiKey = decryptedData.api_key;
      apiSecret = decryptedData.api_secret;
      passphrase = decryptedData.passphrase;

      logger.info('[REST] E2E decryption successful', {
        user_uid: req.body.user_uid,
        exchange: req.body.exchange
      });
    } else {
      // Plaintext mode (backward compatible)
      logger.warn('[REST] Processing PLAINTEXT credential submission', {
        user_uid: req.body.user_uid,
        exchange: req.body.exchange,
        security: 'TLS only - vulnerable to VPS MITM if attestation not verified'
      });

      apiKey = req.body.api_key;
      apiSecret = req.body.api_secret;
      passphrase = req.body.passphrase;
    }

    // Validate with existing schema
    const validation = CreateUserConnectionRequestSchema.safeParse({
      user_uid: req.body.user_uid,
      exchange: req.body.exchange,
      label: req.body.label || `${req.body.exchange} account`,
      api_key: apiKey,
      api_secret: apiSecret,
      passphrase: passphrase
    });

    if (!validation.success) {
      logger.warn('[REST] Invalid request', {
        errors: validation.error.issues
      });

      return res.status(400).json({
        success: false,
        error: 'Invalid request',
        details: validation.error.issues
      });
    }

    const data = validation.data;

    // Call existing EnclaveWorker method
    const worker = container.resolve(EnclaveWorker);
    await worker.createUserConnection({
      userUid: data.user_uid,
      exchange: data.exchange,
      label: data.label,
      apiKey: data.api_key,
      apiSecret: data.api_secret,
      passphrase: data.passphrase
    });

    logger.info('[REST] Connection created successfully', {
      user_uid: data.user_uid,
      exchange: data.exchange
    });

    return res.json({
      success: true,
      user_uid: data.user_uid,
      exchange: data.exchange,
      message: 'Credentials encrypted and stored in enclave'
    });

  } catch (error: any) {
    logger.error('[REST] Connection creation failed:', error);

    return res.status(500).json({
      success: false,
      error: error.message || 'Failed to create connection'
    });
  }
});

/**
 * Load TLS credentials from enclave memory
 */
async function loadTlsCredentials(): Promise<https.ServerOptions> {
  try {
    const tlsService = container.resolve(TlsKeyGeneratorService);
    const credentials = await tlsService.getCredentials();

    return {
      key: credentials.privateKey,
      cert: credentials.certificate
    };
  } catch (error) {
    logger.warn('[REST] Failed to load enclave-generated TLS credentials, falling back to file-based certs');

    // Fallback to file-based certs for development
    const certPath = process.env.TLS_CERT_PATH || '/app/certs/cert.pem';
    const keyPath = process.env.TLS_KEY_PATH || '/app/certs/key.pem';

    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      return {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath)
      };
    }

    throw new Error('No TLS credentials available (neither enclave-generated nor file-based)');
  }
}

/**
 * Start HTTPS REST server
 * TLS terminates INSIDE the enclave, VPS only sees encrypted traffic
 */
export async function startRestServer(port: number = 3050): Promise<https.Server> {
  const tlsOptions = await loadTlsCredentials();

  const server = https.createServer(tlsOptions, app);

  server.listen(port, '0.0.0.0', () => {
    logger.info(`🔒 HTTPS REST server listening on https://0.0.0.0:${port}`);
    logger.info('✅ TLS terminated INSIDE enclave - VPS cannot intercept');
    logger.info('✅ E2E encryption available for maximum security');
    logger.info('📝 Endpoints:');
    logger.info('   - GET  /api/v1/attestation (get SEV-SNP attestation + E2E public key)');
    logger.info('   - POST /api/v1/credentials/connect (submit credentials, plaintext or E2E encrypted)');
  });

  return server;
}
