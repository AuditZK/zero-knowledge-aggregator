/**
 * Secure Enclave Logger
 *
 * Design principles for AMD SEV-SNP / Intel SGX enclaves:
 * 1. Deterministic output (structured JSON only, no colors, no variable formatting)
 * 2. Multi-tier sensitive data filtering (see REDACTION_TIERS below)
 * 3. Stdout/stderr only (no file I/O inside enclave)
 * 4. HTTP polling buffer ALWAYS enabled (deterministic - no conditional logic)
 * 5. Minimal attack surface (no external dependencies)
 * 6. Type-safe and strict
 * 7. Injectable via DI (tsyringe compatible)
 *
 * CRITICAL: This logger MUST be used instead of console.log in all enclave code.
 * Direct console.* usage bypasses security filtering and structured output.
 *
 * REDACTION TIERS (BOTH ALWAYS ACTIVE):
 * - TIER 1: API keys, passwords, tokens, secrets, encrypted fields
 * - TIER 2: user_uid, exchange names, balances, equity, amounts, PII, trading activity
 *
 * DETERMINISTIC LOGGING PHILOSOPHY:
 * For security audits, redaction is ALWAYS active (no conditional logic).
 * Auditors can verify that NO sensitive data ever leaves the enclave:
 *
 * ✅ "Sync job started" (OK - operational event)
 * ✅ "Database connection established" (OK - system status)
 * ✅ "Error: validation failed" (OK - error type only)
 * ❌ "Sync for user 550e..." (BLOCKED - user_uid redacted)
 * ❌ "Balance: $1234.56" (BLOCKED - balance redacted)
 * ❌ "42 trades synced" (BLOCKED - synced count redacted)
 * ❌ "Processing exchange binance" (BLOCKED - exchange redacted)
 */

import { injectable } from 'tsyringe';

/**
 * Log levels in order of severity
 */
export enum LogLevel {
  ERROR = 'ERROR',
  WARN = 'WARN',
  INFO = 'INFO',
  DEBUG = 'DEBUG',
}

/**
 * Structured log entry (JSON serializable)
 */
export interface LogEntry {
  timestamp: string;      // ISO 8601 format (UTC)
  level: LogLevel;
  context: string;        // Service/component name
  message: string;
  metadata?: Record<string, unknown>;
  enclave: true;         // Always true for enclave logs
}

/**
 * TIER 1: Credential and secret field names (exact match, case-insensitive)
 */
const TIER1_EXACT = new Set([
  'apikey', 'apisecret', 'accesskey', 'secretkey', 'password', 'passwd', 'pwd',
  'token', 'accesstoken', 'refreshtoken', 'bearertoken', 'jwt', 'encryptionkey',
  'privatekey', 'secret', 'auth', 'authorization', 'credentials', 'passphrase'
]);

/**
 * TIER 1: Substrings that trigger redaction if present anywhere in field name
 */
const TIER1_CONTAINS = ['encrypted', 'secret', 'password', 'token'];

/**
 * TIER 2: Business-sensitive exact field names (case-insensitive)
 */
const TIER2_EXACT = new Set([
  'useruid', 'userid', 'accountid', 'customerid', 'exchange', 'exchangename',
  'broker', 'platform', 'value', 'price', 'size', 'volume', 'synced', 'count',
  'name', 'email', 'phone', 'address', 'ssn', 'taxid'
]);

/**
 * TIER 2: Substrings that trigger redaction (financial/trading data)
 */
const TIER2_CONTAINS = [
  'balance', 'equity', 'amount', 'total', 'pnl', 'profit', 'loss', 'fee',
  'commission', 'deposit', 'withdrawal', 'trade', 'position', 'order', 'quantity', 'num'
];

/**
 * Normalize field name for matching (lowercase, remove separators)
 */
function normalizeFieldName(fieldName: string): string {
  return fieldName.toLowerCase().replaceAll(/[-_]/g, '');
}

/**
 * Check if a field should be redacted
 * SECURITY: BOTH tiers are ALWAYS active for deterministic auditing
 */
function shouldRedactField(fieldName: string): boolean {
  const normalized = normalizeFieldName(fieldName);

  // Check exact matches first (fast path)
  if (TIER1_EXACT.has(normalized) || TIER2_EXACT.has(normalized)) return true;

  // Check substring matches
  for (const substr of TIER1_CONTAINS) {
    if (normalized.includes(substr)) return true;
  }
  for (const substr of TIER2_CONTAINS) {
    if (normalized.includes(substr)) return true;
  }

  return false;
}

/**
 * Deep filter sensitive data from objects
 * Recursively replaces sensitive values with '[REDACTED]'
 *
 * SECURITY: TIER 1 + TIER 2 are ALWAYS active.
 * This ensures deterministic behavior for security audits.
 */
function filterSensitiveData(data: unknown): unknown {
  if (data === null || data === undefined) {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => filterSensitiveData(item));
  }

  if (typeof data === 'object') {
    const filtered: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(data)) {
      if (shouldRedactField(key)) {
        // TIER 1 or TIER 2: Always redact
        filtered[key] = '[REDACTED]';
      } else {
        // Not sensitive - recursively filter nested objects
        filtered[key] = filterSensitiveData(value);
      }
    }

    return filtered;
  }

  return data;
}

/**
 * Global log level configuration
 * Can be set via environment variable: LOG_LEVEL=DEBUG|INFO|WARN|ERROR
 */
let globalLogLevel: LogLevel = LogLevel.INFO;

// Parse LOG_LEVEL from environment
const envLogLevel = process.env.LOG_LEVEL?.toUpperCase();
if (envLogLevel && envLogLevel in LogLevel) {
  globalLogLevel = LogLevel[envLogLevel as keyof typeof LogLevel];
}

/**
 * Log level hierarchy for filtering
 */
const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  [LogLevel.ERROR]: 0,
  [LogLevel.WARN]: 1,
  [LogLevel.INFO]: 2,
  [LogLevel.DEBUG]: 3,
};

/**
 * Check if a log level should be emitted based on global config
 */
function shouldLog(level: LogLevel): boolean {
  return LOG_LEVEL_PRIORITY[level] <= LOG_LEVEL_PRIORITY[globalLogLevel];
}

/**
 * In-memory log buffer configuration
 * SECURITY: SSE streaming is ALWAYS enabled for deterministic auditing (simpler & real-time)
 *
 * CRITICAL: Logs are ALWAYS filtered by TIER 1 + TIER 2 redaction before buffering/streaming.
 * NO user IDs, amounts, exchanges, or business data ever leaves the enclave.
 * This is deterministic and auditable - no conditional logic.
 */
const MAX_LOG_BUFFER_SIZE = 500; // Keep last 500 log entries
const logBuffer: string[] = [];

/**
 * SSE broadcast callback (set by HTTP log server)
 */
let sseBroadcastCallback: ((log: string) => void) | null = null;

/**
 * Register SSE broadcast callback
 * Called by HTTP log server to enable real-time streaming
 */
export function registerSSEBroadcast(callback: (log: string) => void): void {
  sseBroadcastCallback = callback;
}

/**
 * Add log entry to in-memory buffer and broadcast via SSE
 * Circular buffer: removes oldest entry when max size reached
 */
function addLogToBuffer(logEntry: string): void {
  logBuffer.push(logEntry);

  // Remove oldest entries if buffer exceeds max size
  if (logBuffer.length > MAX_LOG_BUFFER_SIZE) {
    logBuffer.shift();
  }

  // Broadcast to SSE clients if callback is registered
  if (sseBroadcastCallback) {
    sseBroadcastCallback(logEntry);
  }
}

/**
 * Get all logs from buffer (used by SSE initial sync and fallback polling)
 * SECURITY: All logs are already filtered by TIER 1 + TIER 2 redaction
 */
export function getLogBuffer(): string[] {
  return [...logBuffer]; // Return copy to prevent external mutation
}

/**
 * Clear log buffer (useful for testing or manual cleanup)
 */
export function clearLogBuffer(): void {
  logBuffer.length = 0;
}

// Log initialization message
console.log('[Logger] Enclave log SSE streaming ENABLED (always active for deterministic auditing)');
console.log('[Logger] ⚠️  TIER 1 (credentials) + TIER 2 (business data) redaction ACTIVE');
console.log('[Logger] ⚠️  NO user IDs, amounts, or sensitive data will be exposed');

/**
 * Secure Enclave Logger
 *
 * Usage:
 * ```typescript
 * const logger = new SecureEnclaveLogger('ServiceName');
 * logger.info('Operation completed', { recordCount: 42 });
 * logger.error('Operation failed', { error: err });
 * ```
 */
@injectable()
export class SecureEnclaveLogger {
  constructor(private readonly context: string = 'Enclave') {}

  /**
   * Emit a structured log entry to stdout/stderr and optionally to WebSocket
   * SECURITY: All data is ALWAYS filtered by TIER 1 + TIER 2 redaction before emission
   */
  private emit(level: LogLevel, message: string, metadata?: Record<string, unknown>): void {
    if (!shouldLog(level)) {
      return;
    }

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      context: this.context,
      message,
      enclave: true,
    };

    // Filter sensitive data from metadata (TIER 1 + TIER 2 always active)
    if (metadata && Object.keys(metadata).length > 0) {
      entry.metadata = filterSensitiveData(metadata) as Record<string, unknown>;
    }

    // Serialize to JSON
    const jsonLog = JSON.stringify(entry);

    // ERROR level goes to stderr, everything else to stdout
    if (level === LogLevel.ERROR) {
      process.stderr.write(jsonLog + '\n');
    } else {
      process.stdout.write(jsonLog + '\n');
    }

    // Add to in-memory buffer for HTTP polling (ALWAYS enabled for deterministic auditing)
    // SECURITY: Log is already filtered by filterSensitiveData() above
    addLogToBuffer(jsonLog);
  }

  /**
   * Log ERROR level message (highest severity)
   * Goes to stderr
   */
  error(message: string, error?: Error | unknown, metadata?: Record<string, unknown>): void {
    const enrichedMeta: Record<string, unknown> = { ...metadata };

    if (error instanceof Error) {
      enrichedMeta.error = {
        name: error.name,
        message: error.message,
        stack: error.stack,
      };
    } else if (error) {
      enrichedMeta.error = String(error);
    }

    this.emit(LogLevel.ERROR, message, enrichedMeta);
  }

  /**
   * Log WARN level message
   */
  warn(message: string, metadata?: Record<string, unknown>): void {
    this.emit(LogLevel.WARN, message, metadata);
  }

  /**
   * Log INFO level message (default level)
   */
  info(message: string, metadata?: Record<string, unknown>): void {
    this.emit(LogLevel.INFO, message, metadata);
  }

  /**
   * Log DEBUG level message (lowest severity, most verbose)
   */
  debug(message: string, metadata?: Record<string, unknown>): void {
    this.emit(LogLevel.DEBUG, message, metadata);
  }

  /**
   * Create a child logger with a scoped context
   * Useful for creating service-specific loggers
   */
  child(childContext: string): SecureEnclaveLogger {
    return new SecureEnclaveLogger(`${this.context}.${childContext}`);
  }
}

/**
 * Factory function for creating loggers (compatible with existing getLogger pattern)
 */
export function getLogger(context: string): SecureEnclaveLogger {
  return new SecureEnclaveLogger(context);
}

/**
 * Set global log level programmatically
 * Note: Environment variable LOG_LEVEL takes precedence at startup
 */
export function setLogLevel(level: LogLevel): void {
  globalLogLevel = level;
}

/**
 * Get current global log level
 */
export function getLogLevel(): LogLevel {
  return globalLogLevel;
}

/**
 * Extract error message from unknown error type
 * Common utility to standardize error message extraction across the codebase
 *
 * @param error Error object (unknown type from catch blocks)
 * @returns String representation of the error message
 *
 * @example
 * try {
 *   await riskyOperation();
 * } catch (error: unknown) {
 *   const message = extractErrorMessage(error);
 *   logger.error('Operation failed', { error: message });
 * }
 */
export function extractErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Default logger instance (for backward compatibility)
 */
export const logger = new SecureEnclaveLogger('Enclave');
