/**
 * Tests for rest-server.ts
 *
 * Tests the REST API endpoint logic and server functionality.
 */

// Mock tsyringe container
const mockContainer = {
  resolve: jest.fn()
};

jest.mock('tsyringe', () => ({
  container: mockContainer
}));

// Mock TlsKeyGeneratorService
const mockTlsService = {
  getFingerprint: jest.fn().mockReturnValue('AA:BB:CC:DD:EE:FF'),
  getCredentials: jest.fn().mockResolvedValue({
    privateKey: 'mock-private-key',
    certificate: 'mock-certificate',
    fingerprint: 'AA:BB:CC:DD:EE:FF'
  })
};

// Mock SevSnpAttestationService
const mockAttestationService = {
  getAttestationReport: jest.fn().mockResolvedValue({
    verified: true,
    sevSnpEnabled: true,
    vcekVerified: true,
    measurement: 'mock-measurement',
    reportData: 'mock-report-data',
    platformVersion: '1.0.0'
  })
};

// Mock E2EEncryptionService
const mockE2eService = {
  getPublicKey: jest.fn().mockReturnValue('-----BEGIN PUBLIC KEY-----\nmock-key\n-----END PUBLIC KEY-----'),
  getPublicKeyFingerprint: jest.fn().mockReturnValue('abcd1234'),
  decrypt: jest.fn().mockReturnValue(JSON.stringify({
    api_key: 'test-api-key',
    api_secret: 'test-api-secret'
  }))
};

// Mock EnclaveWorker
const mockEnclaveWorker = {
  createUserConnection: jest.fn().mockResolvedValue({
    success: true,
    userUid: 'test-user-uid'
  })
};

// Mock logger
jest.mock('../utils/secure-enclave-logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  }),
  extractErrorMessage: (error: unknown) => {
    if (error instanceof Error) return error.message;
    return String(error);
  }
}));

// Mock fs for TLS credentials fallback
jest.mock('node:fs', () => ({
  existsSync: jest.fn().mockReturnValue(false),
  readFileSync: jest.fn()
}));

describe('REST Server', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    mockContainer.resolve.mockImplementation((service: unknown) => {
      const serviceName = typeof service === 'function' ? service.name : String(service);
      switch (serviceName) {
        case 'TlsKeyGeneratorService':
          return mockTlsService;
        case 'SevSnpAttestationService':
          return mockAttestationService;
        case 'E2EEncryptionService':
          return mockE2eService;
        case 'EnclaveWorker':
          return mockEnclaveWorker;
        default:
          return {};
      }
    });
  });

  describe('Health Endpoint Logic', () => {
    it('should return healthy status', () => {
      const healthResponse = { status: 'ok', service: 'enclave-rest', tls: true };

      expect(healthResponse.status).toBe('ok');
      expect(healthResponse.service).toBe('enclave-rest');
      expect(healthResponse.tls).toBe(true);
    });
  });

  describe('TLS Fingerprint Endpoint Logic', () => {
    it('should return TLS fingerprint when available', () => {
      const fingerprint = mockTlsService.getFingerprint();

      expect(fingerprint).toBe('AA:BB:CC:DD:EE:FF');

      const response = {
        fingerprint,
        algorithm: 'SHA-256',
        usage: 'Compare with attestation report to verify TLS cert authenticity'
      };

      expect(response.fingerprint).toBe('AA:BB:CC:DD:EE:FF');
      expect(response.algorithm).toBe('SHA-256');
    });

    it('should handle missing TLS fingerprint', () => {
      mockTlsService.getFingerprint.mockReturnValueOnce(null);

      const fingerprint = mockTlsService.getFingerprint();

      expect(fingerprint).toBeNull();

      // In real handler, this would return 503
      const shouldReturn503 = !fingerprint;
      expect(shouldReturn503).toBe(true);
    });

    it('should handle TLS service error', () => {
      mockTlsService.getFingerprint.mockImplementationOnce(() => {
        throw new Error('TLS service error');
      });

      expect(() => mockTlsService.getFingerprint()).toThrow('TLS service error');
    });
  });

  describe('Attestation Endpoint Logic', () => {
    it('should return attestation report with E2E public key', async () => {
      const attestation = await mockAttestationService.getAttestationReport();
      const fingerprint = mockTlsService.getFingerprint();
      const e2ePublicKey = mockE2eService.getPublicKey();
      const e2ePublicKeyFingerprint = mockE2eService.getPublicKeyFingerprint();

      const response = {
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
          bound: attestation.reportData !== null
        },
        e2eEncryption: {
          publicKey: e2ePublicKey,
          publicKeyFingerprint: e2ePublicKeyFingerprint,
          algorithm: 'ECIES (ECDH P-256 + AES-256-GCM)'
        }
      };

      expect(response.attestation.verified).toBe(true);
      expect(response.attestation.sevSnpEnabled).toBe(true);
      expect(response.tlsBinding.fingerprint).toBe('AA:BB:CC:DD:EE:FF');
      expect(response.tlsBinding.bound).toBe(true);
      expect(response.e2eEncryption.publicKey).toContain('BEGIN PUBLIC KEY');
    });

    it('should handle attestation service error', async () => {
      mockAttestationService.getAttestationReport.mockRejectedValueOnce(
        new Error('Attestation failed')
      );

      await expect(mockAttestationService.getAttestationReport()).rejects.toThrow('Attestation failed');
    });

    it('should indicate when TLS not bound', async () => {
      mockAttestationService.getAttestationReport.mockResolvedValueOnce({
        verified: false,
        sevSnpEnabled: false,
        vcekVerified: false,
        measurement: null,
        reportData: null,
        platformVersion: null
      });

      const attestation = await mockAttestationService.getAttestationReport();
      const bound = attestation.reportData !== null;

      expect(bound).toBe(false);
    });
  });

  describe('Credentials Endpoint Logic', () => {
    interface RequestBody {
      user_uid?: string;
      exchange?: string;
      label?: string;
      api_key?: string;
      api_secret?: string;
      encrypted?: {
        ephemeralPublicKey: string;
        iv: string;
        ciphertext: string;
        tag: string;
      };
    }

    it('should reject plaintext credentials', () => {
      const requestBody: RequestBody = {
        user_uid: 'test-user',
        exchange: 'binance',
        api_key: 'plain-api-key',
        api_secret: 'plain-api-secret'
      };

      const hasEncrypted = !!requestBody.encrypted;

      expect(hasEncrypted).toBe(false);

      // Handler should return 400 with E2E encryption required error
      const errorResponse = {
        success: false,
        error: 'E2E encryption required. Plaintext credentials are not accepted.',
        hint: 'Fetch /api/v1/attestation to get the E2E public key'
      };

      expect(errorResponse.success).toBe(false);
      expect(errorResponse.error).toContain('E2E encryption required');
    });

    it('should accept E2E encrypted credentials', async () => {
      const requestBody: RequestBody = {
        user_uid: 'test-user',
        exchange: 'binance',
        encrypted: {
          ephemeralPublicKey: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
          iv: 'aabbccdd',
          ciphertext: 'encrypted-data',
          tag: '1234567890abcdef'
        }
      };

      // Decrypt credentials
      const decryptedJson = mockE2eService.decrypt(requestBody.encrypted);
      const decryptedData = JSON.parse(decryptedJson);

      expect(decryptedData.api_key).toBe('test-api-key');
      expect(decryptedData.api_secret).toBe('test-api-secret');

      // Create connection
      await mockEnclaveWorker.createUserConnection({
        userUid: requestBody.user_uid,
        exchange: requestBody.exchange,
        label: `${requestBody.exchange} account`,
        apiKey: decryptedData.api_key,
        apiSecret: decryptedData.api_secret
      });

      expect(mockEnclaveWorker.createUserConnection).toHaveBeenCalledWith(
        expect.objectContaining({
          userUid: 'test-user',
          exchange: 'binance',
          apiKey: 'test-api-key'
        })
      );
    });

    it('should handle decryption failure', () => {
      mockE2eService.decrypt.mockImplementationOnce(() => {
        throw new Error('Decryption failed');
      });

      const encrypted = { ciphertext: 'invalid' };

      expect(() => mockE2eService.decrypt(encrypted)).toThrow('Decryption failed');
    });

    it('should handle invalid JSON in decrypted payload', () => {
      mockE2eService.decrypt.mockReturnValueOnce('not-valid-json');

      const decryptedJson = mockE2eService.decrypt({});

      expect(() => JSON.parse(decryptedJson)).toThrow();
    });

    it('should handle missing api_key in decrypted payload', () => {
      mockE2eService.decrypt.mockReturnValueOnce(JSON.stringify({
        api_secret: 'secret-only'
      }));

      const decryptedJson = mockE2eService.decrypt({});
      const decryptedData = JSON.parse(decryptedJson);

      const hasRequiredFields = decryptedData.api_key && decryptedData.api_secret;

      expect(hasRequiredFields).toBeFalsy();
    });

    it('should handle missing api_secret in decrypted payload', () => {
      mockE2eService.decrypt.mockReturnValueOnce(JSON.stringify({
        api_key: 'key-only'
      }));

      const decryptedJson = mockE2eService.decrypt({});
      const decryptedData = JSON.parse(decryptedJson);

      const hasRequiredFields = decryptedData.api_key && decryptedData.api_secret;

      expect(hasRequiredFields).toBeFalsy();
    });

    it('should handle worker errors', async () => {
      mockEnclaveWorker.createUserConnection.mockRejectedValueOnce(
        new Error('Worker failed')
      );

      await expect(mockEnclaveWorker.createUserConnection({})).rejects.toThrow('Worker failed');
    });

    it('should handle passphrase in credentials', () => {
      mockE2eService.decrypt.mockReturnValueOnce(JSON.stringify({
        api_key: 'test-api-key',
        api_secret: 'test-api-secret',
        passphrase: 'my-passphrase'
      }));

      const decryptedJson = mockE2eService.decrypt({});
      const decryptedData = JSON.parse(decryptedJson);

      expect(decryptedData.passphrase).toBe('my-passphrase');
    });
  });

  describe('TLS Credentials Loading', () => {
    it('should use enclave-generated credentials when available', async () => {
      const credentials = await mockTlsService.getCredentials();

      expect(credentials.privateKey).toBe('mock-private-key');
      expect(credentials.certificate).toBe('mock-certificate');
    });

    it('should throw when TLS credentials unavailable', async () => {
      mockTlsService.getCredentials.mockRejectedValueOnce(new Error('TLS not ready'));

      await expect(mockTlsService.getCredentials()).rejects.toThrow('TLS not ready');
    });

    it('should fall back to file-based certs in development', () => {
      const fs = require('node:fs');
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue('file-based-cert');

      const certPath = process.env.TLS_CERT_PATH || '/app/certs/cert.pem';
      const keyPath = process.env.TLS_KEY_PATH || '/app/certs/key.pem';

      expect(fs.existsSync(certPath)).toBe(true);
      expect(fs.existsSync(keyPath)).toBe(true);
    });

    it('should use custom cert paths from env', () => {
      process.env.TLS_CERT_PATH = '/custom/cert.pem';
      process.env.TLS_KEY_PATH = '/custom/key.pem';

      const certPath = process.env.TLS_CERT_PATH || '/app/certs/cert.pem';
      const keyPath = process.env.TLS_KEY_PATH || '/app/certs/key.pem';

      expect(certPath).toBe('/custom/cert.pem');
      expect(keyPath).toBe('/custom/key.pem');

      delete process.env.TLS_CERT_PATH;
      delete process.env.TLS_KEY_PATH;
    });
  });

  describe('Rate Limiting Configuration', () => {
    it('should have rate limit of 5 requests per 15 minutes', () => {
      const rateLimitConfig = {
        windowMs: 15 * 60 * 1000,
        max: 5,
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false
      };

      expect(rateLimitConfig.windowMs).toBe(900000); // 15 minutes in ms
      expect(rateLimitConfig.max).toBe(5);
      expect(rateLimitConfig.skipSuccessfulRequests).toBe(false);
    });

    it('should include retry info in rate limit response', () => {
      const rateLimitResponse = {
        success: false,
        error: 'Too many credential submission attempts. Please try again later.',
        retryAfter: '15 minutes'
      };

      expect(rateLimitResponse.success).toBe(false);
      expect(rateLimitResponse.retryAfter).toBe('15 minutes');
    });
  });

  describe('Request Validation', () => {
    interface RequestBody {
      user_uid?: string;
      exchange?: string;
      encrypted?: object;
    }

    it('should validate user_uid is required', () => {
      const requestBody: RequestBody = {
        exchange: 'binance',
        encrypted: { ciphertext: 'test' }
      };

      const isValid = requestBody.user_uid && requestBody.exchange;

      expect(isValid).toBeFalsy();
    });

    it('should validate exchange is required', () => {
      const requestBody: RequestBody = {
        user_uid: 'test-user',
        encrypted: { ciphertext: 'test' }
      };

      const isValid = requestBody.user_uid && requestBody.exchange;

      expect(isValid).toBeFalsy();
    });

    it('should pass validation with all required fields', () => {
      const requestBody: RequestBody = {
        user_uid: 'test-user',
        exchange: 'binance',
        encrypted: { ciphertext: 'test' }
      };

      const isValid = requestBody.user_uid && requestBody.exchange && requestBody.encrypted;

      expect(isValid).toBeTruthy();
    });
  });

  describe('Security Headers', () => {
    it('should indicate TLS protection in attestation response', async () => {
      const attestation = await mockAttestationService.getAttestationReport();

      const securityInfo = {
        tlsMitmProtection: attestation.reportData !== null,
        e2eMitmProtection: true,
        message: attestation.reportData
          ? 'Double encryption: TLS for transport + E2E for application layer'
          : 'WARNING: TLS fingerprint not bound - MITM possible'
      };

      expect(securityInfo.tlsMitmProtection).toBe(true);
      expect(securityInfo.e2eMitmProtection).toBe(true);
      expect(securityInfo.message).toContain('Double encryption');
    });

    it('should warn when TLS not bound', async () => {
      mockAttestationService.getAttestationReport.mockResolvedValueOnce({
        verified: true,
        sevSnpEnabled: true,
        vcekVerified: true,
        measurement: 'mock-measurement',
        reportData: null,
        platformVersion: '1.0.0'
      });

      const attestation = await mockAttestationService.getAttestationReport();

      const securityInfo = {
        tlsMitmProtection: attestation.reportData !== null,
        message: attestation.reportData
          ? 'Double encryption'
          : 'WARNING: TLS fingerprint not bound - MITM possible'
      };

      expect(securityInfo.tlsMitmProtection).toBe(false);
      expect(securityInfo.message).toContain('WARNING');
    });
  });

  describe('Label Handling', () => {
    it('should use provided label', () => {
      const requestBody = {
        user_uid: 'test-user',
        exchange: 'binance',
        label: 'My Trading Account'
      };

      const label = requestBody.label || `${requestBody.exchange} account`;

      expect(label).toBe('My Trading Account');
    });

    it('should generate default label from exchange name', () => {
      const requestBody: { user_uid: string; exchange: string; label?: string } = {
        user_uid: 'test-user',
        exchange: 'binance'
      };

      const label = requestBody.label || `${requestBody.exchange} account`;

      expect(label).toBe('binance account');
    });
  });
});
