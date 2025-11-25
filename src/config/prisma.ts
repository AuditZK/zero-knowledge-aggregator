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

  // Set up Prisma logging with typed events
  // @ts-ignore - Prisma event typing has issues with strictNullChecks
  prisma.$on('query', (e: PrismaQueryEvent) => {
    dbLogger.debug('Query executed', {
      query: e.query,
      params: e.params,
      duration: e.duration,
    });
  });

  // @ts-ignore - Prisma event typing has issues with strictNullChecks
  prisma.$on('info', (e: PrismaLogEvent) => {
    dbLogger.info(e.message);
  });

  // @ts-ignore - Prisma event typing has issues with strictNullChecks
  prisma.$on('warn', (e: PrismaLogEvent) => {
    dbLogger.warn(e.message);
  });

  // @ts-ignore - Prisma event typing has issues with strictNullChecks
  prisma.$on('error', (e: PrismaErrorEvent) => {
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
  } catch (error: any) {
    dbLogger.error('Database connection failed', error, {
      errorName: error.name,
      errorMessage: error.message,
    });
    return false;
  }
};

export { prisma };