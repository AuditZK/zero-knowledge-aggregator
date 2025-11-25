import { getLogger } from '../utils/secure-enclave-logger';
import * as fs from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import crypto from 'crypto';

const logger = getLogger('MemoryProtection');
const execAsync = promisify(exec);

export class MemoryProtectionService {
  private static mlockSupported = false;
  private static coreDumpsDisabled = false;
  private static ptraceProtected = false;

  static async initialize(): Promise<void> {
    logger.info('[MEMORY_PROTECTION] Initializing...');

    await this.disableCoreDumps();
    await this.enablePtraceProtection();
    this.checkMlockSupport();
    this.registerCleanupHandlers();

    logger.info('[MEMORY_PROTECTION] Initialized', {
      coreDumps: this.coreDumpsDisabled,
      ptrace: this.ptraceProtected,
      mlock: this.mlockSupported
    });
  }

  private static async disableCoreDumps(): Promise<void> {
    try {
      if (process.setrlimit) {
        process.setrlimit('core', { soft: 0, hard: 0 });
        this.coreDumpsDisabled = true;
        logger.info('[MEMORY_PROTECTION] ✓ Core dumps disabled');
        return;
      }

      try {
        await execAsync('ulimit -c 0');
        this.coreDumpsDisabled = true;
        logger.info('[MEMORY_PROTECTION] ✓ Core dumps disabled via ulimit');
      } catch {
        logger.warn('[MEMORY_PROTECTION] ⚠ Core dumps may be enabled - configure at OS level');
      }
    } catch (error: any) {
      logger.error('[MEMORY_PROTECTION] Failed to disable core dumps', { error: error.message });
    }
  }

  private static async enablePtraceProtection(): Promise<void> {
    try {
      if (process.platform !== 'linux') {return;}

      const ptraceScopePath = '/proc/sys/kernel/yama/ptrace_scope';
      if (!fs.existsSync(ptraceScopePath)) {return;}

      const scope = fs.readFileSync(ptraceScopePath, 'utf8').trim();
      if (scope === '2' || scope === '3') {
        this.ptraceProtected = true;
        logger.info(`[MEMORY_PROTECTION] ✓ Ptrace protection active (scope=${scope})`);
      } else {
        logger.warn(`[MEMORY_PROTECTION] ⚠ Weak ptrace protection (scope=${scope})`);
      }
    } catch (error: any) {
      logger.error('[MEMORY_PROTECTION] Ptrace protection check failed', { error: error.message });
    }
  }

  private static checkMlockSupport(): void {
    try {
      if (process.platform === 'linux' && fs.existsSync('/proc/self/status')) {
        const status = fs.readFileSync('/proc/self/status', 'utf8');
        const vmLck = status.match(/VmLck:\s+(\d+)/);
        if (vmLck) {
          this.mlockSupported = true;
          logger.info('[MEMORY_PROTECTION] mlock available');
        } else {
          logger.warn('[MEMORY_PROTECTION] ⚠ mlock not available (missing CAP_IPC_LOCK)');
        }
      }
    } catch (error: any) {
      logger.warn('[MEMORY_PROTECTION] Could not check mlock', { error: error.message });
    }
  }

  static wipeBuffer(buffer: Buffer): void {
    if (!Buffer.isBuffer(buffer)) {return;}
    try {
      crypto.randomFillSync(buffer);
      buffer.fill(0);
      logger.debug(`[MEMORY_PROTECTION] Wiped ${buffer.length} bytes`);
    } catch (error: any) {
      logger.error('[MEMORY_PROTECTION] Buffer wipe failed', { error: error.message });
    }
  }

  static wipeString(str: string): Buffer {
    const buffer = Buffer.from(str, 'utf8');
    this.wipeBuffer(buffer);
    return buffer;
  }

  private static registerCleanupHandlers(): void {
    const cleanup = () => {
      logger.info('[MEMORY_PROTECTION] Cleaning up secrets...');
      if (process.env.ENCRYPTION_KEY) {
        this.wipeString(process.env.ENCRYPTION_KEY);
        delete process.env.ENCRYPTION_KEY;
      }
      if (process.env.JWT_SECRET) {
        this.wipeString(process.env.JWT_SECRET);
        delete process.env.JWT_SECRET;
      }
      logger.info('[MEMORY_PROTECTION] Cleanup completed');
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
      recs.push('Run in AMD SEV-SNP VM for hardware memory encryption');
      recs.push('Enable ASLR and seccomp');
    }
    return recs;
  }
}
