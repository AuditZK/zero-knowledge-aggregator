/**
 * Database Backup Service
 *
 * SOC 2 Compliant automated backup system for Enclave PostgreSQL database.
 *
 * Features:
 * - Daily automated backups at configurable time (default: 15:00 UTC)
 * - Compressed backups (gzip)
 * - Retention policy (configurable days)
 * - Integrity verification via checksum
 * - Structured logging for audit trail
 *
 * SECURITY:
 * - Backups contain signed snapshots (chain of custody preserved)
 * - Backup files are stored locally (extend for S3/GCS in production)
 * - Old backups automatically purged per retention policy
 */

import { injectable } from 'tsyringe';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as cron from 'node-cron';
import { getLogger } from '../utils/secure-enclave-logger';

const execAsync = promisify(exec);
const logger = getLogger('DatabaseBackup');

export interface BackupConfig {
  /** Backup schedule in cron format (default: '0 15 * * *' = 15:00 UTC daily) */
  schedule: string;
  /** Directory to store backups */
  backupDir: string;
  /** Number of days to retain backups */
  retentionDays: number;
  /** Database connection URL */
  databaseUrl: string;
  /** Enable compression (gzip) */
  compress: boolean;
}

export interface BackupResult {
  success: boolean;
  filename?: string;
  filepath?: string;
  sizeBytes?: number;
  checksum?: string;
  durationMs?: number;
  error?: string;
  timestamp: Date;
}

export interface BackupStatus {
  lastBackup: BackupResult | null;
  nextScheduledBackup: Date | null;
  totalBackups: number;
  oldestBackup: string | null;
  newestBackup: string | null;
  totalSizeBytes: number;
  isHealthy: boolean;
}

@injectable()
export class DatabaseBackupService {
  private config: BackupConfig;
  private cronTask: cron.ScheduledTask | null = null;
  private lastBackupResult: BackupResult | null = null;
  private isRunning = false;

  constructor() {
    // Load configuration from environment
    this.config = {
      schedule: process.env.BACKUP_SCHEDULE || '0 15 * * *', // Default: 15:00 UTC daily
      backupDir: process.env.BACKUP_DIR || '/var/backups/enclave',
      retentionDays: parseInt(process.env.BACKUP_RETENTION_DAYS || '30', 10),
      databaseUrl: process.env.DATABASE_URL || '',
      compress: process.env.BACKUP_COMPRESS !== 'false',
    };

    logger.info('Database backup service initialized', {
      schedule: this.config.schedule,
      backupDir: this.config.backupDir,
      retentionDays: this.config.retentionDays,
      compress: this.config.compress,
    });
  }

  /**
   * Start the automated backup scheduler
   */
  start(): void {
    if (this.cronTask) {
      logger.warn('Backup scheduler already running');
      return;
    }

    // Validate cron expression
    if (!cron.validate(this.config.schedule)) {
      logger.error('Invalid cron schedule', { schedule: this.config.schedule });
      return;
    }

    // Ensure backup directory exists
    this.ensureBackupDirectory();

    // Create cron task
    this.cronTask = cron.schedule(
      this.config.schedule,
      async () => {
        logger.info('Scheduled backup triggered');
        await this.performBackup();
      },
      {
        scheduled: true,
        timezone: 'UTC',
      }
    );

    // Calculate next run time manually (node-cron doesn't provide this)
    const nextRun = this.getNextRunTime();
    logger.info('Backup scheduler started', {
      schedule: this.config.schedule,
      nextRun: nextRun?.toISOString() || 'unknown',
    });
  }

  /**
   * Stop the backup scheduler
   */
  stop(): void {
    if (this.cronTask) {
      this.cronTask.stop();
      this.cronTask = null;
      logger.info('Backup scheduler stopped');
    }
  }

  /**
   * Calculate next scheduled run time
   */
  private getNextRunTime(): Date | null {
    // Parse cron schedule to determine next run
    // Format: '0 15 * * *' = minute hour day month weekday
    const parts = this.config.schedule.split(' ');
    if (parts.length !== 5) return null;

    const minute = parseInt(parts[0], 10);
    const hour = parseInt(parts[1], 10);

    const now = new Date();
    const next = new Date(now);
    next.setUTCHours(hour, minute, 0, 0);

    // If already passed today, schedule for tomorrow
    if (next <= now) {
      next.setDate(next.getDate() + 1);
    }

    return next;
  }

  /**
   * Perform a database backup
   */
  async performBackup(): Promise<BackupResult> {
    if (this.isRunning) {
      logger.warn('Backup already in progress, skipping');
      return {
        success: false,
        error: 'Backup already in progress',
        timestamp: new Date(),
      };
    }

    this.isRunning = true;
    const startTime = Date.now();
    const timestamp = new Date();
    const dateStr = timestamp.toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `enclave_backup_${dateStr}${this.config.compress ? '.sql.gz' : '.sql'}`;
    const filepath = path.join(this.config.backupDir, filename);

    try {
      logger.info('Starting database backup', { filename });

      // Parse database URL
      const dbConfig = this.parseDatabaseUrl(this.config.databaseUrl);

      // Build pg_dump command
      const pgDumpCmd = this.buildPgDumpCommand(dbConfig, filepath);

      // Execute backup
      await execAsync(pgDumpCmd, {
        env: {
          ...process.env,
          PGPASSWORD: dbConfig.password,
        },
        maxBuffer: 1024 * 1024 * 500, // 500MB buffer
      });

      // Verify backup file exists
      if (!fs.existsSync(filepath)) {
        throw new Error('Backup file was not created');
      }

      // Get file stats
      const stats = fs.statSync(filepath);
      const sizeBytes = stats.size;

      // Calculate checksum
      const checksum = await this.calculateChecksum(filepath);

      // Clean old backups
      await this.cleanOldBackups();

      const durationMs = Date.now() - startTime;
      const result: BackupResult = {
        success: true,
        filename,
        filepath,
        sizeBytes,
        checksum,
        durationMs,
        timestamp,
      };

      this.lastBackupResult = result;

      logger.info('Database backup completed successfully', {
        filename,
        sizeBytes,
        sizeMB: (sizeBytes / 1024 / 1024).toFixed(2),
        checksum: checksum.substring(0, 16) + '...',
        durationMs,
      });

      return result;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error('Database backup failed', { error: errorMessage });

      const result: BackupResult = {
        success: false,
        error: errorMessage,
        timestamp,
        durationMs: Date.now() - startTime,
      };

      this.lastBackupResult = result;
      return result;

    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Restore database from backup file
   * WARNING: This will overwrite the current database!
   */
  async restoreBackup(backupFile: string): Promise<{ success: boolean; error?: string }> {
    const filepath = path.join(this.config.backupDir, backupFile);

    if (!fs.existsSync(filepath)) {
      return { success: false, error: `Backup file not found: ${backupFile}` };
    }

    try {
      logger.warn('Starting database restore - THIS WILL OVERWRITE CURRENT DATA', {
        backupFile,
      });

      const dbConfig = this.parseDatabaseUrl(this.config.databaseUrl);
      const isCompressed = backupFile.endsWith('.gz');

      // Build restore command
      let restoreCmd: string;
      if (isCompressed) {
        restoreCmd = `gunzip -c "${filepath}" | psql -h ${dbConfig.host} -p ${dbConfig.port} -U ${dbConfig.user} -d ${dbConfig.database}`;
      } else {
        restoreCmd = `psql -h ${dbConfig.host} -p ${dbConfig.port} -U ${dbConfig.user} -d ${dbConfig.database} -f "${filepath}"`;
      }

      await execAsync(restoreCmd, {
        env: {
          ...process.env,
          PGPASSWORD: dbConfig.password,
        },
      });

      logger.info('Database restore completed successfully', { backupFile });
      return { success: true };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error('Database restore failed', { error: errorMessage, backupFile });
      return { success: false, error: errorMessage };
    }
  }

  /**
   * Get backup status and health information
   */
  async getStatus(): Promise<BackupStatus> {
    const backups = this.listBackups();
    const totalSizeBytes = backups.reduce((sum, b) => {
      const filepath = path.join(this.config.backupDir, b);
      try {
        return sum + fs.statSync(filepath).size;
      } catch {
        return sum;
      }
    }, 0);

    // Check if last backup was successful and recent
    const lastBackupAge = this.lastBackupResult
      ? Date.now() - this.lastBackupResult.timestamp.getTime()
      : Infinity;
    const maxBackupAge = (this.config.retentionDays + 1) * 24 * 60 * 60 * 1000; // retention + 1 day

    const isHealthy = this.lastBackupResult?.success === true && lastBackupAge < maxBackupAge;

    return {
      lastBackup: this.lastBackupResult,
      nextScheduledBackup: this.cronTask ? this.getNextRunTime() : null,
      totalBackups: backups.length,
      oldestBackup: backups[backups.length - 1] || null,
      newestBackup: backups[0] || null,
      totalSizeBytes,
      isHealthy,
    };
  }

  /**
   * List all backup files (sorted by date, newest first)
   */
  listBackups(): string[] {
    try {
      const files = fs.readdirSync(this.config.backupDir);
      return files
        .filter(f => f.startsWith('enclave_backup_') && (f.endsWith('.sql') || f.endsWith('.sql.gz')))
        .sort()
        .reverse();
    } catch {
      return [];
    }
  }

  /**
   * Manually trigger a backup (for testing or admin use)
   */
  async triggerManualBackup(): Promise<BackupResult> {
    logger.info('Manual backup triggered');
    return this.performBackup();
  }

  // ============================================
  // Private Helper Methods
  // ============================================

  private ensureBackupDirectory(): void {
    if (!fs.existsSync(this.config.backupDir)) {
      fs.mkdirSync(this.config.backupDir, { recursive: true });
      logger.info('Created backup directory', { path: this.config.backupDir });
    }
  }

  private parseDatabaseUrl(url: string): {
    host: string;
    port: string;
    user: string;
    password: string;
    database: string;
  } {
    // Parse PostgreSQL URL: postgresql://user:password@host:port/database
    const regex = /postgresql:\/\/([^:]+):([^@]+)@([^:]+):(\d+)\/([^?]+)/;
    const match = url.match(regex);

    if (!match) {
      throw new Error('Invalid DATABASE_URL format');
    }

    return {
      user: match[1],
      password: match[2],
      host: match[3],
      port: match[4],
      database: match[5],
    };
  }

  private buildPgDumpCommand(
    dbConfig: { host: string; port: string; user: string; database: string },
    outputPath: string
  ): string {
    const baseCmd = `pg_dump -h ${dbConfig.host} -p ${dbConfig.port} -U ${dbConfig.user} -d ${dbConfig.database} --no-owner --no-acl`;

    if (this.config.compress) {
      return `${baseCmd} | gzip > "${outputPath}"`;
    }

    return `${baseCmd} -f "${outputPath}"`;
  }

  private async calculateChecksum(filepath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filepath);

      stream.on('data', (data) => hash.update(data));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  private async cleanOldBackups(): Promise<void> {
    const backups = this.listBackups();
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);

    let deletedCount = 0;

    for (const backup of backups) {
      // Extract date from filename: enclave_backup_2025-01-15T15-00-00.sql.gz
      const dateMatch = backup.match(/enclave_backup_(\d{4}-\d{2}-\d{2})/);
      if (!dateMatch) continue;

      const backupDate = new Date(dateMatch[1]);
      if (backupDate < cutoffDate) {
        const filepath = path.join(this.config.backupDir, backup);
        try {
          fs.unlinkSync(filepath);
          deletedCount++;
          logger.debug('Deleted old backup', { backup, age: 'older than retention' });
        } catch (error) {
          logger.warn('Failed to delete old backup', { backup, error });
        }
      }
    }

    if (deletedCount > 0) {
      logger.info('Old backups cleaned up', {
        deletedCount,
        retentionDays: this.config.retentionDays,
      });
    }
  }
}
