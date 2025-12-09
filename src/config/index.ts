import dotenv from 'dotenv';
import { ServerConfig, DatabaseConfig } from '../types';
import { getLogger } from '../utils/secure-enclave-logger';

dotenv.config();

const logger = getLogger('Config');

// CRITICAL: All required environment variables for production
const requiredEnvVars = [
  'DATABASE_URL',
  'JWT_SECRET',
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
  logger.error('FATAL: Missing required environment variables', undefined, {
    missing_vars: missingVars,
    required_vars: requiredEnvVars
  });
  logger.error('Please configure all required environment variables before starting the service');
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
  jwtSecret: process.env.JWT_SECRET!, // Required - validated at startup
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
  logLevel: process.env.LOG_LEVEL || 'info',
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  dataRetentionDays: parseInt(process.env.DATA_RETENTION_DAYS || '30', 10),
};

export const databaseConfig: DatabaseConfig = {
  url: process.env.DATABASE_URL!, // Validated at startup
  ssl: process.env.DB_SSL === 'true',
  // Connection pool size for concurrent gRPC requests and sync operations
  maxConnections: parseInt(process.env.DB_MAX_CONNECTIONS || '50', 10),
  idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT_MS || '30000', 10),
};

export const isDevelopment = serverConfig.nodeEnv === 'development';
export const isProduction = serverConfig.nodeEnv === 'production';
export const isTest = serverConfig.nodeEnv === 'test';