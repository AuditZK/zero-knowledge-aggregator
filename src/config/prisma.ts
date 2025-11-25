import { PrismaClient } from '@prisma/client';
import { getLogger } from '../utils/secure-enclave-logger';
import { databaseConfig } from './index';

const dbLogger = getLogger('Database');

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

export { prisma };