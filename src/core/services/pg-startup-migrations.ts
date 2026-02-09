import { PrismaClient } from '@prisma/client';
import { getLogger } from '../../utils/secure-enclave-logger';

const logger = getLogger('StartupMigrations');

/**
 * Idempotent PostgreSQL migrations that run on every startup.
 * These ensure the database schema matches what Prisma expects,
 * particularly for constraint changes that `prisma generate` alone won't apply.
 */
export async function runStartupMigrations(prisma: PrismaClient): Promise<void> {
  logger.info('Running startup migrations...');

  await migrateMultiAccountConstraints(prisma);

  logger.info('Startup migrations completed');
}

/**
 * Multi-account support: Update unique constraints from (userUid, exchange)
 * to (userUid, exchange, label) across all relevant tables.
 *
 * This is idempotent — safe to run on every startup.
 */
async function migrateMultiAccountConstraints(prisma: PrismaClient): Promise<void> {
  const migrations = [
    {
      table: 'exchange_connections',
      oldConstraint: 'exchange_connections_userUid_exchange_key',
      newConstraint: 'exchange_connections_userUid_exchange_label_key',
      columns: '"userUid", "exchange", "label"',
    },
    {
      table: 'snapshot_data',
      oldConstraint: 'snapshot_data_userUid_timestamp_exchange_key',
      newConstraint: 'snapshot_data_userUid_timestamp_exchange_label_key',
      columns: '"userUid", "timestamp", "exchange", "label"',
    },
    {
      table: 'sync_statuses',
      oldConstraint: 'sync_statuses_userUid_exchange_key',
      newConstraint: 'sync_statuses_userUid_exchange_label_key',
      columns: '"userUid", "exchange", "label"',
    },
    {
      table: 'sync_rate_limit_logs',
      oldConstraint: 'sync_rate_limit_logs_userUid_exchange_key',
      newConstraint: 'sync_rate_limit_logs_userUid_exchange_label_key',
      columns: '"userUid", "exchange", "label"',
    },
  ];

  for (const { table, oldConstraint, newConstraint, columns } of migrations) {
    try {
      // Check if old constraint exists
      const oldExists = await constraintExists(prisma, oldConstraint);
      const newExists = await constraintExists(prisma, newConstraint);

      if (oldExists && !newExists) {
        logger.info(`Migrating constraint on ${table}: dropping ${oldConstraint}, creating ${newConstraint}`);
        await prisma.$executeRawUnsafe(`ALTER TABLE ${table} DROP CONSTRAINT "${oldConstraint}"`);
        await prisma.$executeRawUnsafe(`ALTER TABLE ${table} ADD CONSTRAINT "${newConstraint}" UNIQUE (${columns})`);
        logger.info(`Constraint migrated on ${table}`);
      } else if (!oldExists && !newExists) {
        logger.info(`Creating missing constraint ${newConstraint} on ${table}`);
        await prisma.$executeRawUnsafe(`ALTER TABLE ${table} ADD CONSTRAINT "${newConstraint}" UNIQUE (${columns})`);
        logger.info(`Constraint created on ${table}`);
      } else if (newExists) {
        logger.debug(`Constraint ${newConstraint} already exists on ${table} — skipping`);
      }
    } catch (error) {
      logger.error(`Failed to migrate constraint on ${table}`, error);
      throw error;
    }
  }
}

async function constraintExists(prisma: PrismaClient, constraintName: string): Promise<boolean> {
  const result = await prisma.$queryRaw<{ count: bigint }[]>`
    SELECT COUNT(*)::bigint as count FROM pg_constraint WHERE conname = ${constraintName}
  `;
  return Number(result[0]?.count ?? 0) > 0;
}
