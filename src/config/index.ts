import dotenv from 'dotenv';
import { execSync } from 'node:child_process';
import { ServerConfig, DatabaseConfig } from '../types';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('Config');

/**
 * Load configuration from GCP VM Metadata
 * Used in production instead of .env files for enhanced security
 */
function loadFromGcpMetadata(key: string): string | undefined {
  try {
    const result = execSync(
      `curl -sf -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/${key}`,
      { encoding: 'utf-8', timeout: 5000 }
    );
    return result.trim() || undefined;
  } catch (error) {
    // Metadata not available (not on GCP or key doesn't exist)
    logger.debug(`GCP metadata key '${key}' not found or not on GCP`, { error });
    return undefined;
  }
}

/**
 * Get environment variable with fallback to GCP metadata in production
 * - Production: GCP Metadata ONLY (no .env)
 * - Development: .env file
 */
function getEnvVar(key: string, envKey?: string): string | undefined {
  const actualKey = envKey || key;

  if (process.env.NODE_ENV === 'production') {
    // Production: Read from GCP metadata only
    const value = loadFromGcpMetadata(key);
    if (value) {
      logger.info(`Loaded ${actualKey} from GCP metadata`, { source: 'gcp-metadata' });
    }
    return value;
  } else {
    // Development: Use .env file
    dotenv.config();
    return process.env[actualKey];
  }
}

// Load configuration based on environment
if (process.env.NODE_ENV === 'production') {
  logger.info('Production mode: Loading configuration from GCP VM metadata');
} else {
  logger.info('Development mode: Loading configuration from .env file');
  dotenv.config();
}

// Load all environment variables
const DATABASE_URL = getEnvVar('database-url', 'DATABASE_URL') || process.env.DATABASE_URL;
const JWT_SECRET = getEnvVar('jwt-secret', 'JWT_SECRET') || process.env.JWT_SECRET;
const _ENCRYPTION_KEY = getEnvVar('encryption-key', 'ENCRYPTION_KEY') || process.env.ENCRYPTION_KEY;
const LOG_LEVEL = getEnvVar('log-level', 'LOG_LEVEL') || process.env.LOG_LEVEL;

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
    config_source: process.env.NODE_ENV === 'production' ? 'GCP Metadata' : '.env file'
  });
  logger.error('Please configure all required environment variables before starting the service');

  if (process.env.NODE_ENV === 'production') {
    logger.error('For production, add variables to GCP VM metadata:');
    logger.error('  gcloud compute instances add-metadata <INSTANCE> --metadata=encryption-key=<VALUE>');
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
  port: parseInt(process.env.PORT || '3005', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  apiPrefix: process.env.API_PREFIX || '/api/v1',
  corsOrigin: parseCorsOrigin(process.env.CORS_ORIGIN),
  jwtSecret: JWT_SECRET!,
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
  logLevel: LOG_LEVEL || 'info',
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  dataRetentionDays: parseInt(process.env.DATA_RETENTION_DAYS || '30', 10),
};

export const databaseConfig: DatabaseConfig = {
  url: DATABASE_URL!,
  ssl: process.env.DB_SSL === 'true',
  maxConnections: parseInt(process.env.DB_MAX_CONNECTIONS || '50', 10),
  idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT_MS || '30000', 10),
};

// Export encryption key for EncryptionService
export const ENCRYPTION_KEY = _ENCRYPTION_KEY!;

export const isDevelopment = serverConfig.nodeEnv === 'development';
export const isProduction = serverConfig.nodeEnv === 'production';
export const isTest = serverConfig.nodeEnv === 'test';
