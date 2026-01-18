import {
  SyncJobRequestSchema,
  AggregatedMetricsRequestSchema,
  SnapshotTimeSeriesRequestSchema,
  CreateUserConnectionRequestSchema,
  HealthCheckRequestSchema,
  formatValidationError,
  validateRequest,
} from '../../validation/grpc-schemas';
import { z } from 'zod';

describe('gRPC Validation Schemas', () => {
  describe('User UID validation', () => {
    const testUserUid = (uid: string, expected: boolean) => {
      const result = AggregatedMetricsRequestSchema.safeParse({ user_uid: uid });
      expect(result.success).toBe(expected);
    };

    it('should accept valid Clerk IDs', () => {
      testUserUid('user_2abc123def456xyz789', true);
      testUserUid('user_ABCDEFGHIJ', true);
      testUserUid('user_abcdefghij1234567890', true);
    });

    it('should accept valid UUIDs', () => {
      testUserUid('550e8400-e29b-41d4-a716-446655440000', true);
      testUserUid('6ba7b810-9dad-11d1-80b4-00c04fd430c8', true);
      testUserUid('F47AC10B-58CC-4372-A567-0E02B2C3D479', true);
    });

    it('should accept valid CUIDs', () => {
      testUserUid('cjld2cjxh0000qzrmn831i7rn', true);
      testUserUid('cm1234567890abcdefghij', true);
    });

    it('should reject invalid user IDs', () => {
      testUserUid('', false);
      testUserUid('invalid', false);
      testUserUid('user_', false);
      testUserUid('user_abc', false); // Too short
      testUserUid('12345', false);
      testUserUid('not-a-valid-format', false);
    });
  });

  describe('SyncJobRequestSchema', () => {
    it('should validate minimal request', () => {
      const result = SyncJobRequestSchema.safeParse({
        user_uid: 'user_2abc123def456xyz789',
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.type).toBe('incremental'); // Default
      }
    });

    it('should validate with exchange', () => {
      const result = SyncJobRequestSchema.safeParse({
        user_uid: 'user_2abc123def456xyz789',
        exchange: 'binance',
      });
      expect(result.success).toBe(true);
    });

    it('should transform type to lowercase', () => {
      const result = SyncJobRequestSchema.safeParse({
        user_uid: 'user_2abc123def456xyz789',
        type: 'HISTORICAL',
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.type).toBe('historical');
      }
    });

    it('should reject invalid exchange format', () => {
      const result = SyncJobRequestSchema.safeParse({
        user_uid: 'user_2abc123def456xyz789',
        exchange: 'INVALID EXCHANGE!',
      });
      expect(result.success).toBe(false);
    });
  });

  describe('AggregatedMetricsRequestSchema', () => {
    it('should validate with user_uid only', () => {
      const result = AggregatedMetricsRequestSchema.safeParse({
        user_uid: 'user_2abc123def456xyz789',
      });
      expect(result.success).toBe(true);
    });

    it('should validate with exchange filter', () => {
      const result = AggregatedMetricsRequestSchema.safeParse({
        user_uid: 'user_2abc123def456xyz789',
        exchange: 'kraken',
      });
      expect(result.success).toBe(true);
    });
  });

  describe('SnapshotTimeSeriesRequestSchema', () => {
    const validUserId = 'user_2abc123def456xyz789';
    const now = Date.now();
    const oneWeekAgo = now - 7 * 24 * 60 * 60 * 1000;

    it('should validate without date range', () => {
      const result = SnapshotTimeSeriesRequestSchema.safeParse({
        user_uid: validUserId,
      });
      expect(result.success).toBe(true);
    });

    it('should validate with valid date range', () => {
      const result = SnapshotTimeSeriesRequestSchema.safeParse({
        user_uid: validUserId,
        start_date: oneWeekAgo.toString(),
        end_date: now.toString(),
      });
      expect(result.success).toBe(true);
    });

    it('should transform timestamps to numbers', () => {
      const result = SnapshotTimeSeriesRequestSchema.safeParse({
        user_uid: validUserId,
        start_date: oneWeekAgo.toString(),
        end_date: now.toString(),
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(typeof result.data.start_date).toBe('number');
        expect(typeof result.data.end_date).toBe('number');
      }
    });

    it('should reject if end_date before start_date', () => {
      const result = SnapshotTimeSeriesRequestSchema.safeParse({
        user_uid: validUserId,
        start_date: now.toString(),
        end_date: oneWeekAgo.toString(),
      });
      expect(result.success).toBe(false);
    });

    it('should reject date range over 5 years', () => {
      const sixYearsAgo = now - 6 * 365 * 24 * 60 * 60 * 1000;
      const result = SnapshotTimeSeriesRequestSchema.safeParse({
        user_uid: validUserId,
        start_date: sixYearsAgo.toString(),
        end_date: now.toString(),
      });
      expect(result.success).toBe(false);
    });
  });

  describe('CreateUserConnectionRequestSchema', () => {
    const validRequest = {
      user_uid: 'user_2abc123def456xyz789',
      exchange: 'binance',
      label: 'My Trading Account',
      api_key: 'abc123xyz',
      api_secret: 'secret456',
    };

    it('should validate complete request', () => {
      const result = CreateUserConnectionRequestSchema.safeParse(validRequest);
      expect(result.success).toBe(true);
    });

    it('should validate with optional passphrase', () => {
      const result = CreateUserConnectionRequestSchema.safeParse({
        ...validRequest,
        passphrase: 'mypassphrase',
      });
      expect(result.success).toBe(true);
    });

    it('should reject missing required fields', () => {
      const result = CreateUserConnectionRequestSchema.safeParse({
        user_uid: 'user_2abc123def456xyz789',
        // Missing exchange, label, api_key, api_secret
      });
      expect(result.success).toBe(false);
    });

    it('should reject empty api_key', () => {
      const result = CreateUserConnectionRequestSchema.safeParse({
        ...validRequest,
        api_key: '',
      });
      expect(result.success).toBe(false);
    });

    it('should reject api_key over 500 chars', () => {
      const result = CreateUserConnectionRequestSchema.safeParse({
        ...validRequest,
        api_key: 'a'.repeat(501),
      });
      expect(result.success).toBe(false);
    });
  });

  describe('HealthCheckRequestSchema', () => {
    it('should validate empty object', () => {
      const result = HealthCheckRequestSchema.safeParse({});
      expect(result.success).toBe(true);
    });

    it('should reject extra properties (strict mode)', () => {
      const result = HealthCheckRequestSchema.safeParse({
        unexpected: 'field',
      });
      expect(result.success).toBe(false);
    });
  });

  describe('formatValidationError', () => {
    it('should format single error', () => {
      const schema = z.object({ name: z.string() });
      const result = schema.safeParse({ name: 123 });

      if (!result.success) {
        const message = formatValidationError(result.error);
        expect(message).toContain('Validation failed');
        expect(message).toContain('name');
      }
    });

    it('should format multiple errors', () => {
      const schema = z.object({
        name: z.string(),
        age: z.number(),
      });
      const result = schema.safeParse({ name: 123, age: 'invalid' });

      if (!result.success) {
        const message = formatValidationError(result.error);
        expect(message).toContain('name');
        expect(message).toContain('age');
      }
    });

    it('should handle empty issues array', () => {
      const emptyError = { issues: [] } as unknown as z.ZodError;
      const message = formatValidationError(emptyError);
      expect(message).toBe('Validation failed: Unknown error');
    });
  });

  describe('validateRequest', () => {
    const schema = z.object({ value: z.number() });

    it('should return success with valid data', () => {
      const result = validateRequest(schema, { value: 42 });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.value).toBe(42);
      }
    });

    it('should return error with invalid data', () => {
      const result = validateRequest(schema, { value: 'not a number' });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toContain('Validation failed');
      }
    });
  });
});
