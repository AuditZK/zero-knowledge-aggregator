import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';
import type { LogMetadata } from '../types';

// CRITICAL FIX: Increase max listeners for process event emitters
// Winston's exceptionHandlers and rejectionHandlers add global listeners
// Multiple logger instances (created via DI) exceed the default limit of 10
process.setMaxListeners(50);

/**
 * Professional Logger Service
 * Replaces console.log/error with structured logging
 */
export class LoggerService {
  private logger: winston.Logger;
  private context: string;

  constructor(context: string = 'App') {
    this.context = context;

    // Define log format
    const logFormat = winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.errors({ stack: true }),
      winston.format.splat(),
      winston.format.json(),
    );

    // Console format (prettier for development)
    const consoleFormat = winston.format.combine(
      winston.format.colorize(),
      winston.format.timestamp({ format: 'HH:mm:ss' }),
      winston.format.printf(({ timestamp, level, message, context, ...meta }) => {
        const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
        return `${timestamp} [${context || 'App'}] ${level}: ${message} ${metaStr}`;
      }),
    );

    // Transport configuration
    const transports: winston.transport[] = [];

    // Console transport (development)
    if (process.env.NODE_ENV !== 'production') {
      transports.push(
        new winston.transports.Console({
          format: consoleFormat,
          level: process.env.LOG_LEVEL || 'debug',
        }),
      );
    }

    // File transport (production)
    if (process.env.NODE_ENV === 'production') {
      // Error logs
      transports.push(
        new DailyRotateFile({
          filename: path.join('logs', 'error-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          level: 'error',
          format: logFormat,
          maxSize: '20m',
          maxFiles: '14d',
          zippedArchive: true,
        }),
      );

      // Combined logs
      transports.push(
        new DailyRotateFile({
          filename: path.join('logs', 'combined-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          format: logFormat,
          maxSize: '20m',
          maxFiles: '14d',
          zippedArchive: true,
        }),
      );

      // Console in production (respects LOG_LEVEL)
      transports.push(
        new winston.transports.Console({
          format: winston.format.simple(),
          level: process.env.LOG_LEVEL || 'warn',
        }),
      );
    }

    // Exception and rejection handlers (only in production with file logging)
    const exceptionHandlers = [];
    const rejectionHandlers = [];

    if (process.env.NODE_ENV === 'production') {
      exceptionHandlers.push(
        new winston.transports.File({
          filename: path.join('logs', 'exceptions.log'),
        })
      );
      rejectionHandlers.push(
        new winston.transports.File({
          filename: path.join('logs', 'rejections.log'),
        })
      );
    } else {
      // In development, just use console for exceptions/rejections
      exceptionHandlers.push(new winston.transports.Console());
      rejectionHandlers.push(new winston.transports.Console());
    }

    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: logFormat,
      defaultMeta: { context: this.context },
      transports,
      exceptionHandlers,
      rejectionHandlers,
    });
  }

  /**
   * Log info message
   */
  info(message: string, meta?: LogMetadata): void {
    this.logger.info(message, { ...meta, context: this.context });
  }

  /**
   * Log warning message
   */
  warn(message: string, meta?: LogMetadata): void {
    this.logger.warn(message, { ...meta, context: this.context });
  }

  /**
   * Log error message
   */
  error(message: string, error?: Error | unknown, meta?: LogMetadata): void {
    const errorMeta: LogMetadata = { ...meta, context: this.context };

    if (error instanceof Error) {
      errorMeta.error = {
        name: error.name,
        message: error.message,
        stack: error.stack,
      };
    } else if (error) {
      errorMeta.error = String(error);
    }

    this.logger.error(message, errorMeta);
  }

  /**
   * Log debug message
   */
  debug(message: string, meta?: LogMetadata): void {
    this.logger.debug(message, { ...meta, context: this.context });
  }

  /**
   * Log verbose message
   */
  verbose(message: string, meta?: LogMetadata): void {
    this.logger.verbose(message, { ...meta, context: this.context });
  }

  /**
   * Create child logger with additional context
   */
  child(childContext: string): LoggerService {
    const childLogger = new LoggerService(`${this.context}:${childContext}`);
    return childLogger;
  }
}

/**
 * Global logger instances cache
 */
const loggers = new Map<string, LoggerService>();

/**
 * Get or create logger for a specific context
 */
export function getLogger(context: string): LoggerService {
  if (!loggers.has(context)) {
    loggers.set(context, new LoggerService(context));
  }
  return loggers.get(context);
}

/**
 * Default logger instance
 */
export const logger = new LoggerService('App');
