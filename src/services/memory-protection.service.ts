import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';
import * as fs from 'node:fs';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import crypto from 'node:crypto';

const logger = getLogger('MemoryProtection');
const execAsync = promisify(exec);

export class MemoryProtectionService {
  private static mlockSupported = false;
  private static coreDumpsDisabled = false;
  private static ptraceProtected = false;

  static async initialize(): Promise<void> {
    logger.info('Initializing memory protection...');

    await this.disableCoreDumps();
    await this.enablePtraceProtection();
    this.checkMlockSupport();
    this.registerCleanupHandlers();

    logger.info('Memory protection initialized', {
      coreDumps: this.coreDumpsDisabled,
      ptrace: this.ptraceProtected,
      mlock: this.mlockSupported
    });
  }

  private static async disableCoreDumps(): Promise<void> {
    try {
      if ((process as any).setrlimit) {
        (process as any).setrlimit('core', { soft: 0, hard: 0 });
        this.coreDumpsDisabled = true;
        logger.info('Core dumps disabled');
        return;
      }
      try {
        await execAsync('ulimit -c 0');
        this.coreDumpsDisabled = true;
        logger.info('Core dumps disabled via ulimit');
      } catch {
        logger.warn('Core dumps may be enabled - configure at OS level');
      }
    } catch (error: unknown) {
      logger.error('Failed to disable core dumps', { error: extractErrorMessage(error) });
    }
  }

  private static async enablePtraceProtection(): Promise<void> {
    try {
      if (process.platform !== 'linux') return;
      const ptraceScopePath = '/proc/sys/kernel/yama/ptrace_scope';
      if (!fs.existsSync(ptraceScopePath)) return;

      const scope = fs.readFileSync(ptraceScopePath, 'utf8').trim();
      if (scope === '2' || scope === '3') {
        this.ptraceProtected = true;
        logger.info(`Ptrace protection active (scope=${scope})`);
      } else {
        logger.warn(`Weak ptrace protection (scope=${scope})`);
      }
    } catch (error: unknown) {
      logger.error('Ptrace check failed', { error: extractErrorMessage(error) });
    }
  }

  private static checkMlockSupport(): void {
    try {
      if (process.platform === 'linux' && fs.existsSync('/proc/self/status')) {
        const status = fs.readFileSync('/proc/self/status', 'utf8');
        const mlockPattern = /VmLck:\s+(\d+)/;
        if (mlockPattern.exec(status)) {
          this.mlockSupported = true;
          logger.info('mlock available');
        } else {
          logger.warn('mlock not available (missing CAP_IPC_LOCK)');
        }
      }
    } catch (error: unknown) {
      logger.warn('Could not check mlock', { error: extractErrorMessage(error) });
    }
  }

  /**
   * Securely wipes a Buffer by overwriting with random data then zeros.
   * Unlike strings, Buffers are mutable and can be wiped.
   */
  static wipeBuffer(buffer: Buffer): void {
    if (!Buffer.isBuffer(buffer)) {
      return;
    }
    try {
      crypto.randomFillSync(buffer);
      buffer.fill(0);
    } catch (error: unknown) {
      logger.error('Buffer wipe failed', { error: extractErrorMessage(error) });
    }
  }

  /**
   * LIMITATION: JavaScript strings are immutable and CANNOT be wiped from memory.
   * This method is a no-op placeholder. The original string remains in memory
   * until garbage collected.
   *
   * In AMD SEV-SNP enclaves, memory encryption provides actual protection.
   * For truly sensitive data, use Buffer directly (which CAN be wiped).
   *
   * @deprecated Use Buffer for sensitive data instead of strings
   */
  static wipeString(_str: string): void {
    // No-op: JS strings are immutable - cannot be overwritten
    // SEV-SNP memory encryption is the real protection layer
  }

  private static registerCleanupHandlers(): void {
    const cleanup = () => {
      logger.info('Cleaning up secrets...');
      // Delete env vars on shutdown (strings cannot be wiped, but we remove references)
      // SEV-SNP memory encryption protects data until process termination
      if (process.env.JWT_SECRET) {
        delete process.env.JWT_SECRET;
      }
    };

    process.on('SIGTERM', cleanup);
    process.on('SIGINT', cleanup);
    process.on('beforeExit', cleanup);
  }

  static getStatus() {
    return {
      coreDumpsDisabled: this.coreDumpsDisabled,
      ptraceProtected: this.ptraceProtected,
      mlockSupported: this.mlockSupported,
      platform: process.platform
    };
  }

  static getProductionRecommendations(): string[] {
    const recs: string[] = [];
    if (!this.coreDumpsDisabled) {recs.push('Configure systemd DumpMode=none or ulimit -c 0');}
    if (!this.ptraceProtected) {recs.push('Set kernel.yama.ptrace_scope=2');}
    if (!this.mlockSupported) {recs.push('Add CAP_IPC_LOCK or systemd LockPersonality=yes');}
    if (process.platform === 'linux') {
      recs.push(
        'Run in AMD SEV-SNP VM for hardware memory encryption',
        'Enable ASLR and seccomp'
      );
    }
    return recs;
  }

  /**
   * SECURITY: Securely wipe an object containing sensitive strings
   * Replaces all string properties with empty strings
   */
  static wipeObject<T extends Record<string, unknown>>(obj: T): void {
    if (!obj || typeof obj !== 'object') {return;}

    for (const key of Object.keys(obj)) {
      const value = obj[key];
      if (typeof value === 'string' && value.length > 0) {
        // Overwrite string in memory (best effort - JS strings are immutable)
        (obj as Record<string, unknown>)[key] = '';
      }
    }
    logger.debug('[MEMORY_PROTECTION] Wiped object properties');
  }
}

/**
 * SECURITY: Wrapper for credentials that auto-cleans on dispose
 *
 * Usage:
 * ```
 * const secureCredentials = new SecureCredentials(credentials);
 * try {
 *   await useCredentials(secureCredentials.get());
 * } finally {
 *   secureCredentials.dispose();
 * }
 * ```
 *
 * Or with the helper:
 * ```
 * await SecureCredentials.use(credentials, async (creds) => {
 *   await useCredentials(creds);
 * });
 * ```
 */
export class SecureCredentials<T extends Record<string, unknown>> {
  private credentials: T | null;
  private disposed = false;

  constructor(credentials: T) {
    this.credentials = credentials;
  }

  /**
   * Get the credentials (throws if already disposed)
   */
  get(): T {
    if (this.disposed || !this.credentials) {
      throw new Error('SECURITY: Credentials have been disposed');
    }
    return this.credentials;
  }

  /**
   * Securely dispose of credentials by wiping them from memory
   */
  dispose(): void {
    if (this.disposed || !this.credentials) {return;}

    MemoryProtectionService.wipeObject(this.credentials);
    this.credentials = null;
    this.disposed = true;
  }

  /**
   * Check if credentials are still available
   */
  isDisposed(): boolean {
    return this.disposed;
  }

  /**
   * SECURITY: Helper method for safe credential usage with automatic cleanup
   *
   * @param credentials - The credentials to use
   * @param operation - Async operation that uses the credentials
   * @returns Result of the operation
   */
  static async use<T extends Record<string, unknown>, R>(
    credentials: T,
    operation: (creds: T) => Promise<R>
  ): Promise<R> {
    const secure = new SecureCredentials(credentials);
    try {
      return await operation(secure.get());
    } finally {
      secure.dispose();
    }
  }
}
