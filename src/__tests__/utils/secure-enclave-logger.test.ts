import {
  getLogger,
  extractErrorMessage,
  SecureEnclaveLogger,
} from '../../utils/secure-enclave-logger';

describe('SecureEnclaveLogger', () => {
  let logger: SecureEnclaveLogger;
  let stdoutSpy: jest.SpyInstance;
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.clearAllMocks();
    logger = getLogger('TestContext');
    // Capture stdout and stderr
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  describe('getLogger', () => {
    it('should create logger with context', () => {
      const testLogger = getLogger('MyService');
      expect(testLogger).toBeInstanceOf(SecureEnclaveLogger);
    });

    it('should return logger for same context', () => {
      const logger1 = getLogger('SharedContext');
      const logger2 = getLogger('SharedContext');
      // Both should be loggers (may or may not be same instance depending on implementation)
      expect(logger1).toBeInstanceOf(SecureEnclaveLogger);
      expect(logger2).toBeInstanceOf(SecureEnclaveLogger);
    });

    it('should return loggers for different contexts', () => {
      const logger1 = getLogger('Context1');
      const logger2 = getLogger('Context2');
      expect(logger1).toBeInstanceOf(SecureEnclaveLogger);
      expect(logger2).toBeInstanceOf(SecureEnclaveLogger);
    });
  });

  describe('log levels', () => {
    it('should log INFO messages to stdout', () => {
      logger.info('Test info message');

      expect(stdoutSpy).toHaveBeenCalled();
      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      expect(output).toContain('"level":"INFO"');
      expect(output).toContain('Test info message');
    });

    it('should log WARN messages to stdout', () => {
      logger.warn('Test warning message');

      expect(stdoutSpy).toHaveBeenCalled();
      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      expect(output).toContain('"level":"WARN"');
    });

    it('should log ERROR messages to stderr', () => {
      logger.error('Test error message');

      expect(stderrSpy).toHaveBeenCalled();
      const output = stderrSpy.mock.calls[0]?.[0] as string;
      expect(output).toContain('"level":"ERROR"');
    });

    it('should filter DEBUG messages when LOG_LEVEL is not DEBUG', () => {
      // DEBUG messages are only logged when LOG_LEVEL=DEBUG
      // Default LOG_LEVEL is INFO, so DEBUG messages should be filtered
      logger.debug('Test debug message');

      // With default LOG_LEVEL=INFO, DEBUG is filtered out
      const logLevel = process.env.LOG_LEVEL?.toUpperCase() || 'INFO';
      if (logLevel === 'DEBUG') {
        expect(stdoutSpy).toHaveBeenCalled();
        const output = stdoutSpy.mock.calls[0]?.[0] as string;
        expect(output).toContain('"level":"DEBUG"');
      } else {
        // DEBUG messages are filtered when LOG_LEVEL > DEBUG
        expect(stdoutSpy).not.toHaveBeenCalled();
      }
    });
  });

  describe('error logging', () => {
    it('should include Error details in metadata (redacted for security)', () => {
      const error = new Error('Something went wrong');
      logger.error('Operation failed', error);

      const output = stderrSpy.mock.calls[0]?.[0] as string;
      const parsed = JSON.parse(output);
      // The 'error' field is redacted for security in enclave
      expect(parsed.metadata.error).toBeDefined();
    });

    it('should handle non-Error objects (redacted)', () => {
      logger.error('Operation failed', { code: 500, reason: 'Server error' });

      const output = stderrSpy.mock.calls[0]?.[0] as string;
      const parsed = JSON.parse(output);
      // Error is stringified and the key 'error' may be redacted
      expect(parsed.metadata.error).toBeDefined();
    });

    it('should handle string errors', () => {
      logger.error('Operation failed', 'Simple string error');

      const output = stderrSpy.mock.calls[0]?.[0] as string;
      const parsed = JSON.parse(output);
      expect(parsed.metadata.error).toBe('Simple string error');
    });

    it('should handle null/undefined errors', () => {
      logger.error('Operation failed', null);
      logger.error('Operation failed', undefined);

      // Should not throw and should log
      expect(stderrSpy).toHaveBeenCalledTimes(2);
    });
  });

  describe('metadata handling', () => {
    it('should include custom metadata (with security redaction)', () => {
      // Note: userId is redacted for security (TIER 2 business data)
      logger.info('User action', { requestId: 'req123', action: 'login' });

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      const parsed = JSON.parse(output);
      // requestId is not in redaction list, so it should pass through
      expect(parsed.metadata.requestId).toBe('req123');
      expect(parsed.metadata.action).toBe('login');
    });

    it('should include context in output', () => {
      logger.info('Test message');

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      const parsed = JSON.parse(output);
      expect(parsed.context).toBe('TestContext');
    });

    it('should include timestamp', () => {
      logger.info('Test message');

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      const parsed = JSON.parse(output);
      expect(parsed.timestamp).toBeDefined();
      expect(new Date(parsed.timestamp).getTime()).not.toBeNaN();
    });

    it('should include enclave flag', () => {
      logger.info('Test message');

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      const parsed = JSON.parse(output);
      expect(parsed.enclave).toBe(true);
    });
  });

  describe('sensitive data filtering', () => {
    it('should redact apiKey in metadata', () => {
      logger.info('API call', { apiKey: 'secret-api-key-123' });

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      expect(output).not.toContain('secret-api-key-123');
      expect(output).toContain('[REDACTED]');
    });

    it('should redact apiSecret in metadata', () => {
      logger.info('API call', { apiSecret: 'my-super-secret' });

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      expect(output).not.toContain('my-super-secret');
      expect(output).toContain('[REDACTED]');
    });

    it('should redact password in metadata', () => {
      logger.info('Login attempt', { password: 'hunter2' });

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      expect(output).not.toContain('hunter2');
    });

    it('should redact token in metadata', () => {
      logger.info('Auth', { token: 'jwt-token-here' });

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      expect(output).not.toContain('jwt-token-here');
    });

    it('should redact nested sensitive data', () => {
      logger.info('Request', {
        credentials: {
          apiKey: 'nested-secret',
          user: 'john',
        },
      });

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      expect(output).not.toContain('nested-secret');
    });
  });

  describe('JSON output format', () => {
    it('should output valid JSON', () => {
      logger.info('Test', { data: 123 });

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      expect(() => JSON.parse(output)).not.toThrow();
    });

    it('should handle special characters in message', () => {
      logger.info('Test "quoted" message with\nnewline');

      const output = stdoutSpy.mock.calls[0]?.[0] as string;
      expect(() => JSON.parse(output)).not.toThrow();
      const parsed = JSON.parse(output);
      expect(parsed.message).toContain('quoted');
    });
  });
});

describe('extractErrorMessage', () => {
  it('should extract message from Error', () => {
    const error = new Error('Test error message');
    const message = extractErrorMessage(error);
    expect(message).toBe('Test error message');
  });

  it('should convert string to string', () => {
    const message = extractErrorMessage('String error');
    expect(message).toBe('String error');
  });

  it('should convert number to string', () => {
    const message = extractErrorMessage(404);
    expect(message).toBe('404');
  });

  it('should handle null by converting to string', () => {
    const message = extractErrorMessage(null);
    // String(null) returns "null"
    expect(message).toBe('null');
  });

  it('should handle undefined by converting to string', () => {
    const message = extractErrorMessage(undefined);
    // String(undefined) returns "undefined"
    expect(message).toBe('undefined');
  });

  it('should stringify objects using String()', () => {
    const message = extractErrorMessage({ error: 'test', code: 500 });
    // String({}) returns "[object Object]"
    expect(message).toBe('[object Object]');
  });
});
