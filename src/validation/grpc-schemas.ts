import { z } from 'zod';

// Accept Clerk user IDs (user_xxx), UUIDs, and CUIDs
// Clerk format: user_[a-zA-Z0-9]{20,40}
// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
// CUID format: c[a-z0-9]{20,30}
const userUidSchema = z.string().min(1).max(100).regex(
  /^(user_[a-zA-Z0-9]{10,50}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|c[a-z0-9]{20,30})$/i,
  'Invalid user UID format (expected Clerk ID, UUID, or CUID)'
);
const exchangeSchema = z.string().min(1).max(50).regex(/^[a-z0-9_-]+$/);
const timestampSchema = z.string().regex(/^\d+$/).transform(val => parseInt(val, 10))
  .refine(val => val > 0 && val < Date.now() + 86400000);

/**
 * SyncJobRequest - Simplified schema
 *
 * NOTE: 'type' is deprecated - sync behavior is now automatic:
 * - IBKR: Auto-backfill from Flex (365 days) on first sync, then current day only
 * - Crypto: Current snapshot only (DailySyncScheduler handles midnight UTC syncs)
 */
export const SyncJobRequestSchema = z.object({
  user_uid: userUidSchema,
  exchange: exchangeSchema.optional(),
  /** @deprecated Sync type is now automatic based on exchange type */
  type: z.enum(['INCREMENTAL', 'HISTORICAL', 'FULL', 'incremental', 'historical', 'full'])
    .transform(val => val.toLowerCase() as 'incremental' | 'historical' | 'full')
    .optional()
    .default('incremental')
});

export const AggregatedMetricsRequestSchema = z.object({
  user_uid: userUidSchema,
  exchange: exchangeSchema.optional()
});

export const SnapshotTimeSeriesRequestSchema = z.object({
  user_uid: userUidSchema,
  exchange: exchangeSchema.optional(),
  start_date: timestampSchema.optional(),
  end_date: timestampSchema.optional()
}).refine(data => !data.start_date || !data.end_date || data.start_date < data.end_date, 'Invalid date range')
  .refine(data => !data.start_date || !data.end_date || (data.end_date - data.start_date) <= 5 * 365 * 24 * 60 * 60 * 1000, 'Max 5 years');

export const CreateUserConnectionRequestSchema = z.object({
  user_uid: userUidSchema,  // Platform provides the user UID (Clerk ID, UUID, or CUID)
  exchange: exchangeSchema,
  label: z.string().min(1).max(100),
  api_key: z.string().min(1).max(500),
  api_secret: z.string().min(1).max(500),
  passphrase: z.string().max(500).optional()
});

export const HealthCheckRequestSchema = z.object({}).strict();

export type ValidatedSyncJobRequest = z.infer<typeof SyncJobRequestSchema>;
export type ValidatedAggregatedMetricsRequest = z.infer<typeof AggregatedMetricsRequestSchema>;
export type ValidatedSnapshotTimeSeriesRequest = z.infer<typeof SnapshotTimeSeriesRequestSchema>;
export type ValidatedCreateUserConnectionRequest = z.infer<typeof CreateUserConnectionRequestSchema>;
export type ValidatedHealthCheckRequest = z.infer<typeof HealthCheckRequestSchema>;

export function formatValidationError(error: z.ZodError): string {
  const errors = error?.issues ?? [];
  if (errors.length === 0) {
    return 'Validation failed: Unknown error';
  }
  return `Validation failed: ${errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ')}`;
}

export function validateRequest<T>(schema: z.ZodSchema<T>, data: unknown):
  { success: true; data: T } | { success: false; error: string } {
  const result = schema.safeParse(data);
  return result.success ? { success: true, data: result.data } : { success: false, error: formatValidationError(result.error) };
}
