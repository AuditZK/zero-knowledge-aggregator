import { PrismaClient, Prisma } from '@prisma/client';
import { getLogger } from '../utils/secure-enclave-logger';
import { databaseConfig } from './index';

const dbLogger = getLogger('Database');

// Transient error codes that warrant retry (PostgreSQL + Prisma)
const TRANSIENT_ERROR_CODES = new Set([
  'P1001', // Can't reach database server
  'P1002', // Database server timed out
  'P1008', // Operations timed out
  'P1017', // Server closed the connection
  'P2024', // Timed out fetching connection from pool
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'ENOTFOUND',
]);

const isTransientError = (error: unknown): boolean => {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    return TRANSIENT_ERROR_CODES.has(error.code);
  }
  if (error instanceof Prisma.PrismaClientInitializationError) {
    return error.message.includes("Can't reach database") ||
           error.message.includes('timed out') ||
           error.message.includes('ECONNREFUSED');
  }
  if (error instanceof Error) {
    return TRANSIENT_ERROR_CODES.has((error as NodeJS.ErrnoException).code || '');
  }
  return false;
};

export interface RetryConfig {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
}

const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxAttempts: 5,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
};

const sleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

export const withRetry = async <T>(
  operation: () => Promise<T>,
  config: Partial<RetryConfig> = {},
  context = 'Database operation'
): Promise<T> => {
  const { maxAttempts, baseDelayMs, maxDelayMs } = { ...DEFAULT_RETRY_CONFIG, ...config };

  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;

      if (!isTransientError(error) || attempt === maxAttempts) {
        throw error;
      }

      const delay = Math.min(baseDelayMs * Math.pow(2, attempt - 1), maxDelayMs);
      dbLogger.warn(`${context} failed (attempt ${attempt}/${maxAttempts}), retrying in ${delay}ms...`, {
        error: lastError.message,
        nextAttempt: attempt + 1,
      });

      await sleep(delay);
    }
  }

  throw lastError;
};

// Prisma event types
interface PrismaQueryEvent {
  timestamp: Date;
  query: string;
  params: string;
  duration: number;
  target: string;
}

interface PrismaLogEvent {
  timestamp: Date;
  message: string;
  target: string;
}

interface PrismaErrorEvent {
  timestamp: Date;
  message: string;
  target: string;
}

let prisma: PrismaClient | null = null;

export const createPrismaClient = (): PrismaClient => {
  if (prisma) {
    return prisma;
  }

  // CRITICAL: Apply connection pooling configuration for production
  const databaseUrl = databaseConfig.url;
  const idleTimeout = databaseConfig.idleTimeoutMillis || 30000;
  const pooledUrl = `${databaseUrl}${databaseUrl?.includes('?') ? '&' : '?'}connection_limit=${databaseConfig.maxConnections}&pool_timeout=${Math.floor(idleTimeout / 1000)}`;

  dbLogger.info('Initializing Prisma with connection pooling', {
    maxConnections: databaseConfig.maxConnections,
    poolTimeout: `${databaseConfig.idleTimeoutMillis}ms`,
  });

  prisma = new PrismaClient({
    datasources: {
      db: {
        url: pooledUrl,
      },
    },
    log: [
      { emit: 'event', level: 'query' },
      { emit: 'event', level: 'info' },
      { emit: 'event', level: 'warn' },
      { emit: 'event', level: 'error' },
    ],
  });

  // Set up Prisma logging with typed events using type assertion
  (prisma.$on as (event: 'query', callback: (e: PrismaQueryEvent) => void) => void)('query', (e) => {
    dbLogger.debug('Query executed', {
      query: e.query,
      params: e.params,
      duration: e.duration,
    });
  });

  (prisma.$on as (event: 'info', callback: (e: PrismaLogEvent) => void) => void)('info', (e) => {
    dbLogger.info(e.message);
  });

  (prisma.$on as (event: 'warn', callback: (e: PrismaLogEvent) => void) => void)('warn', (e) => {
    dbLogger.warn(e.message);
  });

  (prisma.$on as (event: 'error', callback: (e: PrismaErrorEvent) => void) => void)('error', (e) => {
    dbLogger.error('Database error', undefined, { message: e.message, target: e.target });
  });

  return prisma;
};

export const getPrismaClient = (): PrismaClient => {
  if (!prisma) {
    // Auto-initialize if not already done
    dbLogger.info('Auto-initializing Prisma client...');
    return createPrismaClient();
  }
  return prisma;
};

export const closePrismaClient = async (): Promise<void> => {
  if (prisma) {
    await prisma.$disconnect();
    prisma = null;
  }
};

export const testPrismaConnection = async (): Promise<boolean> => {
  try {
    dbLogger.info('Testing connection to PostgreSQL DB with Prisma...');
    const client = getPrismaClient();

    // Test simple query
    await client.$queryRaw`SELECT NOW() as now`;
    dbLogger.info('Database connected successfully with Prisma');
    return true;
  } catch (error) {
    const err = error as Error;
    dbLogger.error('Database connection failed', err, {
      errorName: err.name,
      errorMessage: err.message,
    });
    return false;
  }
};

/**
 * Connects to the database with two-phase retry strategy:
 * - Phase 1: Fast retries (1s, 2s, 4s, 8s, 10s) for transient glitches (~30s)
 * - Phase 2: Slow retries (60s intervals) for longer outages (~1 hour)
 */
export const connectWithRetry = async (): Promise<{ client: PrismaClient; snapshotCount: number }> => {
  const doConnect = async () => {
    const client = getPrismaClient();
    await client.$queryRaw`SELECT 1`;
    const snapshotCount = await client.snapshotData.count();
    return { client, snapshotCount };
  };

  // Phase 1: Fast retries for transient glitches
  dbLogger.info('Connecting to database (Phase 1: fast retries)...');
  try {
    return await withRetry(doConnect, {
      maxAttempts: 6,
      baseDelayMs: 1000,
      maxDelayMs: 10000,
    }, 'Database connection (fast)');
  } catch {
    dbLogger.warn('Fast retries exhausted, switching to long-term retry strategy...');
  }

  // Phase 2: Slow retries for longer outages (~1 hour)
  dbLogger.info('Connecting to database (Phase 2: long-term retries, ~1 hour max)...');
  return withRetry(doConnect, {
    maxAttempts: 60,
    baseDelayMs: 60000,
    maxDelayMs: 60000,
  }, 'Database connection (slow)');
};

// Note: prisma instance is accessed via getPrismaClient() - not exported directly