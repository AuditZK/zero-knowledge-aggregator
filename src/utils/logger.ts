import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';
import crypto from 'crypto';
import type { LogMetadata, Trade, Position } from '../types';

// Define log levels
const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define colors for each level
const logColors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'blue',
};

// Tell winston about colors
winston.addColors(logColors);

// Format for console output
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
  winston.format.align(),
  winston.format.printf(info => {
    const { timestamp, level, message, service, correlationId, ...meta } = info;
    let log = `${timestamp} [${level}]`;
    if (service) {
log += ` [${service}]`;
}
    if (correlationId) {
log += ` [${correlationId}]`;
}
    log += ` ${message}`;
    if (Object.keys(meta).length > 0) {
      log += ` ${JSON.stringify(meta)}`;
    }
    return log;
  }),
);

// Format for file output
const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
);

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), 'logs');

// Configure transports
const transports: winston.transport[] = [];

// Console transport - always enabled
transports.push(
  new winston.transports.Console({
    format: consoleFormat,
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  }),
);

// File transports - only in production or if explicitly enabled
if (process.env.NODE_ENV === 'production' || process.env.ENABLE_FILE_LOGS === 'true') {
  // Error logs
  transports.push(
    new DailyRotateFile({
      filename: path.join(logsDir, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      format: fileFormat,
      maxSize: '20m',
      maxFiles: '14d',
      zippedArchive: true,
    }),
  );

  // Combined logs
  transports.push(
    new DailyRotateFile({
      filename: path.join(logsDir, 'combined-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      format: fileFormat,
      maxSize: '20m',
      maxFiles: '7d',
      zippedArchive: true,
    }),
  );

  // Performance logs
  transports.push(
    new DailyRotateFile({
      filename: path.join(logsDir, 'performance-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      level: 'info',
      format: winston.format.combine(
        winston.format((info) => {
          // Only log performance-related messages
          return info.service === 'performance' ? info : false;
        })(),
        fileFormat,
      ),
      maxSize: '20m',
      maxFiles: '7d',
      zippedArchive: true,
    }),
  );
}

// Create the main logger instance
const winstonLogger = winston.createLogger({
  levels: logLevels,
  transports,
  exitOnError: false,
});

// Create correlation ID context
class LogContext {
  private static correlationId: string | null = null;
  private static metadata: LogMetadata = {};

  static setCorrelationId(id?: string) {
    this.correlationId = id || crypto.randomUUID();
  }

  static getCorrelationId(): string | null {
    return this.correlationId;
  }

  static clearCorrelationId() {
    this.correlationId = null;
  }

  static setMetadata(data: LogMetadata) {
    this.metadata = { ...this.metadata, ...data };
  }

  static clearMetadata() {
    this.metadata = {};
  }

  static getMetadata(): LogMetadata {
    return this.metadata;
  }
}

// Professional Logger class
export class Logger {
  private service: string;
  private defaultMeta: LogMetadata;

  constructor(service?: string, defaultMeta?: LogMetadata) {
    this.service = service || 'app';
    this.defaultMeta = defaultMeta || {};
  }

  private log(level: string, message: string, meta?: LogMetadata) {
    const correlationId = LogContext.getCorrelationId();
    const contextMeta = LogContext.getMetadata();

    winstonLogger.log(level, message, {
      service: this.service,
      correlationId,
      ...this.defaultMeta,
      ...contextMeta,
      ...(meta || {}),
    });
  }

  // Standard log levels
  error(message: string, error?: Error | unknown, meta?: LogMetadata) {
    const errorMeta: LogMetadata = error instanceof Error ? {
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
      },
    } : error ? { error: String(error) } : {};

    this.log('error', message, { ...errorMeta, ...meta });
  }

  warn(message: string, meta?: LogMetadata) {
    this.log('warn', message, meta);
  }

  info(message: string, meta?: LogMetadata) {
    this.log('info', message, meta);
  }

  http(message: string, meta?: LogMetadata) {
    this.log('http', message, meta);
  }

  debug(message: string, meta?: LogMetadata) {
    this.log('debug', message, meta);
  }

  // Specialized logging methods
  performance(operation: string, duration: number, meta?: LogMetadata) {
    this.info(`Performance: ${operation}`, {
      operation,
      duration,
      ...meta,
    });
  }

  trade(action: string, tradeData: Partial<Trade>) {
    this.info(`Trade: ${action}`, {
      action,
      trade: tradeData,
    });
  }

  position(action: string, positionData: Partial<Position>) {
    this.info(`Position: ${action}`, {
      action,
      position: positionData,
    });
  }

  sync(exchange: string, status: string, meta?: LogMetadata) {
    this.info(`Sync: ${exchange} - ${status}`, {
      exchange,
      status,
      ...meta,
    });
  }

  database(operation: string, meta?: LogMetadata) {
    this.debug(`Database: ${operation}`, {
      operation,
      ...meta,
    });
  }

  api(method: string, path: string, statusCode?: number, duration?: number, meta?: LogMetadata) {
    const level = statusCode && statusCode >= 500 ? 'error' :
                  statusCode && statusCode >= 400 ? 'warn' : 'http';

    this.log(level, `API: ${method} ${path}`, {
      method,
      path,
      statusCode,
      duration,
      ...meta,
    });
  }

  // Create child logger with additional context
  child(service: string, defaultMeta?: LogMetadata): Logger {
    return new Logger(
      `${this.service}.${service}`,
      { ...this.defaultMeta, ...defaultMeta },
    );
  }

  // Static methods for global context
  static setCorrelationId(id?: string) {
    LogContext.setCorrelationId(id);
  }

  static clearCorrelationId() {
    LogContext.clearCorrelationId();
  }

  static setContext(data: LogMetadata) {
    LogContext.setMetadata(data);
  }

  static clearContext() {
    LogContext.clearMetadata();
  }
}

// Create default logger instance
export const logger = new Logger();

// Export specialized loggers
export const dbLogger = new Logger('database');
export const apiLogger = new Logger('api');
export const syncLogger = new Logger('sync');
export const tradeLogger = new Logger('trade');
export const performanceLogger = new Logger('performance');

// Utility function to measure performance
export function measurePerformance<T>(
  operation: string,
  fn: () => Promise<T>,
  logger: Logger = performanceLogger,
): Promise<T> {
  const start = Date.now();

  return fn()
    .then(result => {
      const duration = Date.now() - start;
      logger.performance(operation, duration, { success: true });
      return result;
    })
    .catch(error => {
      const duration = Date.now() - start;
      logger.performance(operation, duration, { success: false, error: error.message });
      throw error;
    });
}

// Stream for Morgan HTTP logger
export const httpLogStream = {
  write: (message: string) => {
    apiLogger.http(message.trim());
  },
};

export default logger;