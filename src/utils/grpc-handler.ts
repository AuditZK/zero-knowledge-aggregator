/**
 * Generic gRPC Handler Wrapper
 *
 * Reduces boilerplate in enclave-server.ts by factoring common patterns:
 * - Input normalization (gRPC empty strings → undefined)
 * - Zod validation
 * - Logging (request/response/error)
 * - Error handling with proper gRPC status codes
 */

import * as grpc from '@grpc/grpc-js';
import { z } from 'zod';
import { getLogger, extractErrorMessage } from './secure-enclave-logger';

const logger = getLogger('GrpcHandler');

/**
 * Validation result from Zod schema
 */
type ValidationResult<T> =
  | { success: true; data: T }
  | { success: false; error: string };

/**
 * Validate request against Zod schema
 */
export function validateRequest<T>(
  schema: z.ZodType<T>,
  data: unknown
): ValidationResult<T> {
  const result = schema.safeParse(data);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return {
    success: false,
    error: result.error.issues.map((e: z.ZodIssue) => `${e.path.join('.')}: ${e.message}`).join(', ')
  };
}

/**
 * Handler configuration for a gRPC endpoint
 */
export interface GrpcHandlerConfig<TRaw, TValidated, TResult, TResponse> {
  /** Handler name for logging */
  name: string;

  /** Zod schema for validation */
  schema: z.ZodType<TValidated>;

  /** Normalize raw gRPC request (convert empty strings to undefined, etc.) */
  normalize: (raw: TRaw) => unknown;

  /** Execute the business logic */
  execute: (validated: TValidated) => Promise<TResult>;

  /** Convert result to gRPC response format */
  toGrpc: (result: TResult) => TResponse;

  /** Optional: fields to log from request (for debugging) */
  logFields?: (validated: TValidated) => Record<string, unknown>;
}

/**
 * Create a wrapped gRPC handler with validation, logging, and error handling
 */
export function createGrpcHandler<TRaw, TValidated, TResult, TResponse>(
  config: GrpcHandlerConfig<TRaw, TValidated, TResult, TResponse>
): (
  call: grpc.ServerUnaryCall<TRaw, TResponse>,
  callback: grpc.sendUnaryData<TResponse>
) => Promise<void> {
  return async (call, callback) => {
    try {
      // 1. Normalize raw request
      const normalized = config.normalize(call.request);

      // 2. Validate with Zod
      const validation = validateRequest(config.schema, normalized);
      if (!validation.success) {
        logger.warn(`Invalid ${config.name} request`, { error: validation.error });
        callback({ code: grpc.status.INVALID_ARGUMENT, message: validation.error }, null);
        return;
      }

      // 3. Log request (optional fields)
      const logData = config.logFields ? config.logFields(validation.data) : {};
      logger.info(`${config.name} started`, logData);

      // 4. Execute business logic
      const result = await config.execute(validation.data);

      // 5. Convert to gRPC response and return
      callback(null, config.toGrpc(result));
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error(`${config.name} failed`, error);
      callback({ code: grpc.status.INTERNAL, message: errorMessage }, null);
    }
  };
}

/**
 * Normalize gRPC string field: convert empty string to undefined
 */
export function normalizeString(value: string | undefined): string | undefined {
  return value === '' ? undefined : value;
}

/**
 * Normalize gRPC timestamp field: convert "0" or 0 to undefined
 */
export function normalizeTimestamp(value: string | number | undefined): string | undefined {
  if (value === '0' || value === 0 || value === '' || value === undefined) {
    return undefined;
  }
  return String(value);
}
