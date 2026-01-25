import dotenv from 'dotenv';
import { ServerConfig, DatabaseConfig } from '../types';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('Config');

/**
 * Configuration Loading Architecture:
 *
 * PRODUCTION (GCP SEV-SNP VM):
 * 1. scripts/start-enclave.sh reads secrets from GCP VM metadata
 * 2. Exports them as shell environment variables
 * 3. docker-compose passes them to the container via ${VAR}
 * 4. Container reads from process.env
 *
 * DEVELOPMENT:
 * - Reads from .env file via dotenv
 *
 * This avoids .env files in production and keeps secrets in GCP metadata.
 */

// Load .env in development only
if (process.env.NODE_ENV === 'production') {
  logger.info('Production mode: Loading configuration from environment (via start-enclave.sh)');
} else {
  logger.info('Development mode: Loading configuration from .env file');
  dotenv.config();
}

// Load all environment variables
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const _ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const LOG_LEVEL = process.env.LOG_LEVEL;
const BENCHMARK_SERVICE_URL = process.env.BENCHMARK_SERVICE_URL;

// CRITICAL: All required environment variables for production
const requiredEnvVars: Record<string, string | undefined> = {
  DATABASE_URL,
  JWT_SECRET,
  ENCRYPTION_KEY: _ENCRYPTION_KEY,
};

const missingVars = Object.entries(requiredEnvVars)
  .filter(([_, value]) => !value)
  .map(([key]) => key);

if (missingVars.length > 0) {
  logger.error('FATAL: Missing required environment variables', undefined, {
    missing_vars: missingVars,
    environment: process.env.NODE_ENV || 'development',
    config_source: process.env.NODE_ENV === 'production' ? 'start-enclave.sh' : '.env file'
  });
  logger.error('Please configure all required environment variables before starting the service');

  if (process.env.NODE_ENV === 'production') {
    logger.error('For production, use: ./scripts/start-enclave.sh');
    logger.error('Ensure GCP VM metadata contains: database-url, encryption-key, jwt-secret');
  }

  process.exit(1);
}

// Parse CORS origins (supports comma-separated list)
const parseCorsOrigin = (origin?: string): string | string[] => {
  if (!origin) {
    return 'http://localhost:3000';
  }
  const origins = origin.split(',').map(o => o.trim());
  return origins.length === 1 ? origins[0]! : origins;
};

export const serverConfig: ServerConfig = {
  port: Number.parseInt(process.env.PORT || '3005', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  apiPrefix: process.env.API_PREFIX || '/api/v1',
  corsOrigin: parseCorsOrigin(process.env.CORS_ORIGIN),
  jwtSecret: JWT_SECRET!,
  bcryptRounds: Number.parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
  logLevel: LOG_LEVEL || 'info',
  rateLimitWindowMs: Number.parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
  rateLimitMaxRequests: Number.parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  dataRetentionDays: Number.parseInt(process.env.DATA_RETENTION_DAYS || '30', 10),
};

export const databaseConfig: DatabaseConfig = {
  url: DATABASE_URL!,
  ssl: process.env.DB_SSL === 'true',
  maxConnections: Number.parseInt(process.env.DB_MAX_CONNECTIONS || '50', 10),
  idleTimeoutMillis: Number.parseInt(process.env.DB_IDLE_TIMEOUT_MS || '30000', 10),
};

// Export encryption key for EncryptionService
export const ENCRYPTION_KEY = _ENCRYPTION_KEY!;

// Export benchmark service URL for report generation
export const benchmarkServiceUrl = BENCHMARK_SERVICE_URL || 'http://localhost:8080';

export const isDevelopment = serverConfig.nodeEnv === 'development';
export const isProduction = serverConfig.nodeEnv === 'production';
export const isTest = serverConfig.nodeEnv === 'test';
