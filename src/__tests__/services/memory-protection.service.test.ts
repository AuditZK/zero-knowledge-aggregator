import { MemoryProtectionService, SecureCredentials } from '../../services/memory-protection.service';

describe('MemoryProtectionService', () => {
  describe('wipeBuffer', () => {
    it('should wipe buffer contents to zeros', () => {
      const buffer = Buffer.from('secret-data-here');
      const originalLength = buffer.length;

      MemoryProtectionService.wipeBuffer(buffer);

      // Buffer should be all zeros after wipe
      expect(buffer.length).toBe(originalLength);
      for (let i = 0; i < buffer.length; i++) {
        expect(buffer[i]).toBe(0);
      }
    });

    it('should handle empty buffer', () => {
      const buffer = Buffer.alloc(0);

      expect(() => {
        MemoryProtectionService.wipeBuffer(buffer);
      }).not.toThrow();
    });

    it('should not throw on non-buffer input', () => {
      expect(() => {
        MemoryProtectionService.wipeBuffer('not a buffer' as unknown as Buffer);
      }).not.toThrow();

      expect(() => {
        MemoryProtectionService.wipeBuffer(null as unknown as Buffer);
      }).not.toThrow();

      expect(() => {
        MemoryProtectionService.wipeBuffer(undefined as unknown as Buffer);
      }).not.toThrow();
    });

    it('should handle large buffer', () => {
      const buffer = Buffer.alloc(10000, 0xff);

      MemoryProtectionService.wipeBuffer(buffer);

      // All bytes should be zero
      const allZeros = buffer.every(byte => byte === 0);
      expect(allZeros).toBe(true);
    });
  });

  describe('wipeString', () => {
    it('should be a no-op (strings are immutable)', () => {
      const str = 'secret-string';

      // Should not throw
      expect(() => {
        MemoryProtectionService.wipeString(str);
      }).not.toThrow();

      // String is unchanged (immutable)
      expect(str).toBe('secret-string');
    });
  });

  describe('wipeObject', () => {
    it('should replace string properties with empty strings', () => {
      const obj = {
        apiKey: 'secret-api-key',
        apiSecret: 'secret-api-secret',
        username: 'john',
      };

      MemoryProtectionService.wipeObject(obj);

      expect(obj.apiKey).toBe('');
      expect(obj.apiSecret).toBe('');
      expect(obj.username).toBe('');
    });

    it('should handle object with mixed types', () => {
      const obj = {
        name: 'secret',
        count: 42,
        active: true,
        data: null,
      };

      MemoryProtectionService.wipeObject(obj);

      expect(obj.name).toBe('');
      expect(obj.count).toBe(42); // number unchanged
      expect(obj.active).toBe(true); // boolean unchanged
      expect(obj.data).toBeNull(); // null unchanged
    });

    it('should handle empty object', () => {
      const obj = {};

      expect(() => {
        MemoryProtectionService.wipeObject(obj);
      }).not.toThrow();
    });

    it('should handle null or undefined gracefully', () => {
      expect(() => {
        MemoryProtectionService.wipeObject(null as unknown as Record<string, unknown>);
      }).not.toThrow();

      expect(() => {
        MemoryProtectionService.wipeObject(undefined as unknown as Record<string, unknown>);
      }).not.toThrow();
    });

    it('should skip already empty strings', () => {
      const obj = {
        empty: '',
        hasValue: 'secret',
      };

      MemoryProtectionService.wipeObject(obj);

      expect(obj.empty).toBe('');
      expect(obj.hasValue).toBe('');
    });
  });

  describe('getStatus', () => {
    it('should return status object with required fields', () => {
      const status = MemoryProtectionService.getStatus();

      expect(status).toHaveProperty('coreDumpsDisabled');
      expect(status).toHaveProperty('ptraceProtected');
      expect(status).toHaveProperty('mlockSupported');
      expect(status).toHaveProperty('platform');
    });

    it('should return platform from process.platform', () => {
      const status = MemoryProtectionService.getStatus();

      expect(status.platform).toBe(process.platform);
    });

    it('should return boolean values for protection flags', () => {
      const status = MemoryProtectionService.getStatus();

      expect(typeof status.coreDumpsDisabled).toBe('boolean');
      expect(typeof status.ptraceProtected).toBe('boolean');
      expect(typeof status.mlockSupported).toBe('boolean');
    });
  });

  describe('getProductionRecommendations', () => {
    it('should return an array of strings', () => {
      const recommendations = MemoryProtectionService.getProductionRecommendations();

      expect(Array.isArray(recommendations)).toBe(true);
      recommendations.forEach(rec => {
        expect(typeof rec).toBe('string');
      });
    });

    it('should include Linux-specific recommendations on Linux', () => {
      if (process.platform === 'linux') {
        const recommendations = MemoryProtectionService.getProductionRecommendations();

        expect(recommendations.some(r => r.includes('AMD SEV-SNP'))).toBe(true);
        expect(recommendations.some(r => r.includes('ASLR'))).toBe(true);
      }
    });
  });

  describe('initialize', () => {
    it('should complete without throwing', async () => {
      // Initialize is safe to call multiple times
      await expect(MemoryProtectionService.initialize()).resolves.not.toThrow();
    });
  });
});

describe('SecureCredentials', () => {
  describe('constructor and get', () => {
    it('should store and return credentials', () => {
      const creds = { apiKey: 'key123', apiSecret: 'secret456' };
      const secure = new SecureCredentials(creds);

      const retrieved = secure.get();

      expect(retrieved).toBe(creds);
      expect(retrieved.apiKey).toBe('key123');
      expect(retrieved.apiSecret).toBe('secret456');
    });
  });

  describe('dispose', () => {
    it('should wipe credentials on dispose', () => {
      const creds = { apiKey: 'key123', apiSecret: 'secret456' };
      const secure = new SecureCredentials(creds);

      secure.dispose();

      // Original object should be wiped
      expect(creds.apiKey).toBe('');
      expect(creds.apiSecret).toBe('');
    });

    it('should mark as disposed after dispose', () => {
      const creds = { apiKey: 'key123' };
      const secure = new SecureCredentials(creds);

      expect(secure.isDisposed()).toBe(false);

      secure.dispose();

      expect(secure.isDisposed()).toBe(true);
    });

    it('should be safe to call dispose multiple times', () => {
      const creds = { apiKey: 'key123' };
      const secure = new SecureCredentials(creds);

      secure.dispose();

      expect(() => {
        secure.dispose();
      }).not.toThrow();
    });
  });

  describe('get after dispose', () => {
    it('should throw when accessing disposed credentials', () => {
      const creds = { apiKey: 'key123' };
      const secure = new SecureCredentials(creds);

      secure.dispose();

      expect(() => {
        secure.get();
      }).toThrow('SECURITY: Credentials have been disposed');
    });
  });

  describe('isDisposed', () => {
    it('should return false when not disposed', () => {
      const creds = { apiKey: 'key123' };
      const secure = new SecureCredentials(creds);

      expect(secure.isDisposed()).toBe(false);
    });

    it('should return true after dispose', () => {
      const creds = { apiKey: 'key123' };
      const secure = new SecureCredentials(creds);

      secure.dispose();

      expect(secure.isDisposed()).toBe(true);
    });
  });

  describe('static use', () => {
    it('should execute operation with credentials', async () => {
      const creds = { apiKey: 'test-key', apiSecret: 'test-secret' };

      const result = await SecureCredentials.use(creds, async (c) => {
        return `Key: ${c.apiKey}`;
      });

      expect(result).toBe('Key: test-key');
    });

    it('should dispose credentials after operation completes', async () => {
      const creds = { apiKey: 'test-key', apiSecret: 'test-secret' };

      await SecureCredentials.use(creds, async () => {
        // Operation completes
        return 'done';
      });

      // Credentials should be wiped
      expect(creds.apiKey).toBe('');
      expect(creds.apiSecret).toBe('');
    });

    it('should dispose credentials even if operation throws', async () => {
      const creds = { apiKey: 'test-key', apiSecret: 'test-secret' };

      await expect(
        SecureCredentials.use(creds, async () => {
          throw new Error('Operation failed');
        })
      ).rejects.toThrow('Operation failed');

      // Credentials should still be wiped
      expect(creds.apiKey).toBe('');
      expect(creds.apiSecret).toBe('');
    });

    it('should return operation result', async () => {
      const creds = { token: 'abc' };

      const result = await SecureCredentials.use(creds, async (c) => {
        return { processed: true, tokenLength: c.token.length };
      });

      expect(result).toEqual({ processed: true, tokenLength: 3 });
    });

    it('should work with async operations', async () => {
      const creds = { apiKey: 'key' };

      const result = await SecureCredentials.use(creds, async (c) => {
        await new Promise(resolve => setTimeout(resolve, 10));
        return c.apiKey.toUpperCase();
      });

      expect(result).toBe('KEY');
      expect(creds.apiKey).toBe(''); // Wiped after
    });
  });
});
