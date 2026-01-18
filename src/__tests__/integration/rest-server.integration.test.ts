/**
 * Integration tests for rest-server.ts
 *
 * These tests import the actual rest-server module to achieve coverage.
 */

// Mock external dependencies BEFORE importing
jest.mock('tsyringe', () => ({
  container: {
    resolve: jest.fn().mockImplementation((service: unknown) => {
      const serviceName = typeof service === 'function' ? service.name : String(service);
      switch (serviceName) {
        case 'TlsKeyGeneratorService':
          return {
            getFingerprint: jest.fn().mockReturnValue('AA:BB:CC:DD:EE:FF'),
            getCredentials: jest.fn().mockResolvedValue({
              privateKey: '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC\n-----END PRIVATE KEY-----',
              certificate: '-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALQ\n-----END CERTIFICATE-----',
              fingerprint: 'AA:BB:CC:DD:EE:FF'
            })
          };
        case 'SevSnpAttestationService':
          return {
            getAttestationReport: jest.fn().mockResolvedValue({
              verified: true,
              sevSnpEnabled: true,
              vcekVerified: true,
              measurement: 'mock-measurement',
              reportData: 'mock-report-data',
              platformVersion: '1.0.0'
            })
          };
        case 'E2EEncryptionService':
          return {
            getPublicKey: jest.fn().mockReturnValue('-----BEGIN PUBLIC KEY-----\nmock\n-----END PUBLIC KEY-----'),
            getPublicKeyFingerprint: jest.fn().mockReturnValue('abcd1234'),
            decrypt: jest.fn().mockReturnValue(JSON.stringify({
              api_key: 'test-api-key',
              api_secret: 'test-api-secret'
            }))
          };
        case 'EnclaveWorker':
          return {
            createUserConnection: jest.fn().mockResolvedValue({
              success: true,
              userUid: 'test-user-uid'
            })
          };
        default:
          return {};
      }
    }),
    register: jest.fn(),
    registerSingleton: jest.fn()
  },
  injectable: () => (target: unknown) => target,
  singleton: () => (target: unknown) => target,
  inject: () => () => undefined,
  injectAll: () => () => undefined,
  registry: () => (target: unknown) => target
}));

// Mock fs
jest.mock('node:fs', () => ({
  existsSync: jest.fn().mockReturnValue(false),
  readFileSync: jest.fn()
}));

// Mock https
const mockHttpsServer = {
  listen: jest.fn().mockImplementation((_port: number, _host: string, callback: () => void) => {
    if (callback) callback();
  }),
  close: jest.fn().mockImplementation((callback: (err?: Error) => void) => {
    if (callback) callback();
  })
};

jest.mock('node:https', () => ({
  createServer: jest.fn().mockReturnValue(mockHttpsServer)
}));

// Mock express-rate-limit
jest.mock('express-rate-limit', () => {
  return jest.fn().mockImplementation(() => {
    return (_req: unknown, _res: unknown, next: () => void) => {
      next();
    };
  });
});

// Mock logger
jest.mock('../../utils/secure-enclave-logger', () => ({
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

// Mock validation schemas
jest.mock('../../validation/grpc-schemas', () => ({
  CreateUserConnectionRequestSchema: {
    safeParse: jest.fn().mockReturnValue({
      success: true,
      data: {
        user_uid: 'test-user',
        exchange: 'binance',
        label: 'test',
        api_key: 'key',
        api_secret: 'secret'
      }
    })
  }
}));

// Now import the actual module
import { startRestServer } from '../../rest-server';

describe('REST Server Integration', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('startRestServer', () => {
    it('should start the REST server on default port', async () => {
      const server = await startRestServer();

      expect(server).toBeDefined();
      expect(mockHttpsServer.listen).toHaveBeenCalled();
    });

    it('should start the REST server on custom port', async () => {
      const server = await startRestServer(4000);

      expect(server).toBeDefined();
      expect(mockHttpsServer.listen).toHaveBeenCalledWith(4000, '0.0.0.0', expect.any(Function));
    });
  });

  describe('TLS Credentials', () => {
    it('should use enclave-generated TLS credentials', async () => {
      const https = require('node:https');

      await startRestServer();

      expect(https.createServer).toHaveBeenCalled();
    });

    it('should fall back to file-based certs when enclave credentials unavailable', async () => {
      const { container } = require('tsyringe');
      container.resolve.mockImplementation((service: unknown) => {
        const serviceName = typeof service === 'function' ? service.name : String(service);
        if (serviceName === 'TlsKeyGeneratorService') {
          return {
            getFingerprint: jest.fn().mockReturnValue('AA:BB:CC:DD:EE:FF'),
            getCredentials: jest.fn().mockRejectedValue(new Error('Not available'))
          };
        }
        return {};
      });

      const fs = require('node:fs');
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue('mock-cert-content');

      await startRestServer();

      expect(fs.existsSync).toHaveBeenCalled();
    });
  });
});
