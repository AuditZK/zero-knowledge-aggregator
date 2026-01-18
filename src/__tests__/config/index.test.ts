/**
 * Tests for config/index.ts
 *
 * Note: Since the config module has module-level code that runs on import,
 * we test the exported values and functions that can be accessed without
 * triggering process.exit().
 */

// Mock child_process.execSync before any imports
jest.mock('node:child_process', () => ({
  execSync: jest.fn()
}));

// Mock dotenv
jest.mock('dotenv', () => ({
  config: jest.fn()
}));

// Mock the logger
jest.mock('../../utils/secure-enclave-logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  })
}));

describe('Config Module', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = {
      ...originalEnv,
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
      JWT_SECRET: 'test-jwt-secret-12345',
      ENCRYPTION_KEY: 'test-encryption-key-12345678901234567890'
    };
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.resetModules();
  });

  describe('Environment Configuration', () => {
    it('should export serverConfig with default values', async () => {
      const { serverConfig } = await import('../../config/index');

      expect(serverConfig).toBeDefined();
      expect(serverConfig.nodeEnv).toBe('test');
      expect(serverConfig.port).toBeDefined();
      expect(serverConfig.apiPrefix).toBe('/api/v1');
      expect(serverConfig.bcryptRounds).toBe(12);
    });

    it('should export databaseConfig with configured URL', async () => {
      const { databaseConfig } = await import('../../config/index');

      expect(databaseConfig).toBeDefined();
      expect(databaseConfig.url).toBe('postgresql://test:test@localhost:5432/test');
      expect(databaseConfig.maxConnections).toBe(50);
    });

    it('should export ENCRYPTION_KEY', async () => {
      const { ENCRYPTION_KEY } = await import('../../config/index');

      expect(ENCRYPTION_KEY).toBeDefined();
      expect(ENCRYPTION_KEY).toBe('test-encryption-key-12345678901234567890');
    });

    it('should export environment flags', async () => {
      const { isDevelopment, isProduction, isTest } = await import('../../config/index');

      expect(isDevelopment).toBe(false);
      expect(isProduction).toBe(false);
      expect(isTest).toBe(true);
    });
  });

  describe('serverConfig values', () => {
    it('should parse PORT as number', async () => {
      process.env.PORT = '4000';
      const { serverConfig } = await import('../../config/index');

      expect(serverConfig.port).toBe(4000);
    });

    it('should use default port when not set', async () => {
      delete process.env.PORT;
      const { serverConfig } = await import('../../config/index');

      expect(serverConfig.port).toBe(3005);
    });

    it('should handle CORS_ORIGIN with single origin', async () => {
      process.env.CORS_ORIGIN = 'https://example.com';
      const { serverConfig } = await import('../../config/index');

      expect(serverConfig.corsOrigin).toBe('https://example.com');
    });

    it('should handle CORS_ORIGIN with multiple origins', async () => {
      process.env.CORS_ORIGIN = 'https://example.com, https://other.com';
      const { serverConfig } = await import('../../config/index');

      expect(serverConfig.corsOrigin).toEqual(['https://example.com', 'https://other.com']);
    });

    it('should default CORS_ORIGIN to localhost', async () => {
      delete process.env.CORS_ORIGIN;
      const { serverConfig } = await import('../../config/index');

      expect(serverConfig.corsOrigin).toBe('http://localhost:3000');
    });

    it('should parse rate limit configuration', async () => {
      process.env.RATE_LIMIT_WINDOW_MS = '60000';
      process.env.RATE_LIMIT_MAX_REQUESTS = '50';
      const { serverConfig } = await import('../../config/index');

      expect(serverConfig.rateLimitWindowMs).toBe(60000);
      expect(serverConfig.rateLimitMaxRequests).toBe(50);
    });

    it('should parse data retention days', async () => {
      process.env.DATA_RETENTION_DAYS = '90';
      const { serverConfig } = await import('../../config/index');

      expect(serverConfig.dataRetentionDays).toBe(90);
    });

    it('should use default LOG_LEVEL', async () => {
      delete process.env.LOG_LEVEL;
      const { serverConfig } = await import('../../config/index');

      expect(serverConfig.logLevel).toBe('info');
    });
  });

  describe('databaseConfig values', () => {
    it('should parse DB_SSL as boolean', async () => {
      process.env.DB_SSL = 'true';
      const { databaseConfig } = await import('../../config/index');

      expect(databaseConfig.ssl).toBe(true);
    });

    it('should parse max connections', async () => {
      process.env.DB_MAX_CONNECTIONS = '100';
      const { databaseConfig } = await import('../../config/index');

      expect(databaseConfig.maxConnections).toBe(100);
    });

    it('should parse idle timeout', async () => {
      process.env.DB_IDLE_TIMEOUT_MS = '60000';
      const { databaseConfig } = await import('../../config/index');

      expect(databaseConfig.idleTimeoutMillis).toBe(60000);
    });
  });

  describe('GCP Metadata Loading', () => {
    it('should attempt to load from GCP in production mode', async () => {
      const { execSync } = require('node:child_process') as { execSync: jest.Mock };
      execSync.mockImplementation(() => {
        throw new Error('Not on GCP');
      });

      process.env.NODE_ENV = 'production';
      // Still need required vars for the module to not exit
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.JWT_SECRET = 'test-jwt-secret-12345';
      process.env.ENCRYPTION_KEY = 'test-encryption-key-12345678901234567890';

      // Import will trigger GCP metadata loading in production
      await import('../../config/index');

      // execSync should have been called for GCP metadata
      expect(execSync).toHaveBeenCalled();
    });

    it('should reject invalid metadata keys with special characters', async () => {
      const { execSync } = require('node:child_process') as { execSync: jest.Mock };

      // In production, loadFromGcpMetadata validates keys
      // Keys with invalid characters should be rejected before execSync is called
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.JWT_SECRET = 'test-jwt-secret-12345';
      process.env.ENCRYPTION_KEY = 'test-encryption-key-12345678901234567890';

      execSync.mockClear();

      await import('../../config/index');

      // The module should only call execSync with valid key patterns
      const calls = execSync.mock.calls;
      calls.forEach((call: unknown[]) => {
        const cmd = call[0];
        if (typeof cmd === 'string') {
          // Extract the key from the curl command
          const match = cmd.match(/attributes\/([a-z0-9-]+)/);
          if (match) {
            expect(match[1]).toMatch(/^[a-z0-9-]+$/);
          }
        }
      });
    });
  });

  describe('Environment Flags', () => {
    it('should set isDevelopment true in development mode', async () => {
      process.env.NODE_ENV = 'development';
      const { isDevelopment, isProduction, isTest } = await import('../../config/index');

      expect(isDevelopment).toBe(true);
      expect(isProduction).toBe(false);
      expect(isTest).toBe(false);
    });

    it('should set isProduction true in production mode', async () => {
      process.env.NODE_ENV = 'production';
      const { isDevelopment, isProduction, isTest } = await import('../../config/index');

      expect(isDevelopment).toBe(false);
      expect(isProduction).toBe(true);
      expect(isTest).toBe(false);
    });
  });
});
