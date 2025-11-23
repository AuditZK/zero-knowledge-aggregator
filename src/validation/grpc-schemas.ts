import { z } from 'zod';

const uuidSchema = z.string().uuid();
const exchangeSchema = z.string().min(1).max(50).regex(/^[a-z0-9_-]+$/);
const timestampSchema = z.string().regex(/^\d+$/).transform(val => parseInt(val, 10))
  .refine(val => val > 0 && val < Date.now() + 86400000);

export const SyncJobRequestSchema = z.object({
  user_uid: uuidSchema,
  exchange: exchangeSchema.optional(),
  type: z.enum(['INCREMENTAL', 'HISTORICAL', 'FULL']),
  start_date: timestampSchema.optional(),
  end_date: timestampSchema.optional()
}).refine(data => !data.start_date || !data.end_date || data.start_date < data.end_date, 'Invalid date range')
  .refine(data => data.type !== 'HISTORICAL' || (data.start_date && data.end_date), 'HISTORICAL requires dates')
  .refine(data => !data.start_date || !data.end_date || (data.end_date - data.start_date) <= 5 * 365 * 24 * 60 * 60 * 1000, 'Max 5 years');

export const AggregatedMetricsRequestSchema = z.object({
  user_uid: uuidSchema,
  exchange: exchangeSchema.optional()
});

export const HealthCheckRequestSchema = z.object({}).strict();

export type ValidatedSyncJobRequest = z.infer<typeof SyncJobRequestSchema>;
export type ValidatedAggregatedMetricsRequest = z.infer<typeof AggregatedMetricsRequestSchema>;
export type ValidatedHealthCheckRequest = z.infer<typeof HealthCheckRequestSchema>;

export function formatValidationError(error: z.ZodError): string {
  return `Validation failed: ${error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ')}`;
}

export function validateRequest<T>(schema: z.ZodSchema<T>, data: unknown):
  { success: true; data: T } | { success: false; error: string } {
  const result = schema.safeParse(data);
  return result.success ? { success: true, data: result.data } : { success: false, error: formatValidationError(result.error) };
}
