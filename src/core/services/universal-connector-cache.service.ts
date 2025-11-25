import { injectable } from 'tsyringe';
import { IExchangeConnector } from '../../external/interfaces/IExchangeConnector';
import { ExchangeConnectorFactory } from '../../external/factories/ExchangeConnectorFactory';
import { ExchangeCredentials } from '../../types';
import { getLogger } from '../../utils/secure-enclave-logger';
import crypto from 'crypto';

const logger = getLogger('UniversalConnectorCache');

interface CachedConnector {
  connector: IExchangeConnector;
  expires: number;
  createdAt: number;
  lastAccessed: number;
  accessCount: number;
  exchangeType: 'ccxt' | 'custom-broker';
}

interface CacheStats {
  hits: number;
  misses: number;
  evictions: number;
  currentSize: number;
  totalMemoryMB: number;
}

/**
 * Universal Connector Cache Service
 *
 * Caches ALL exchange connector instances (CCXT, IBKR, Alpaca, etc.)
 * to avoid redundant initialization overhead.
 *
 * Architecture:
 * - Crypto exchanges: Cached CCXT connectors
 * - Stock brokers: Cached custom connectors (IBKR Flex, Alpaca, etc.)
 * - Polymorphic: All connectors implement IExchangeConnector interface
 *
 * Benefits:
 * - Reduces memory allocation (no duplicate HTTP clients, rate limiters, etc.)
 * - Faster connector creation (~200ms saved per snapshot)
 * - Reduces garbage collection pressure
 * - Supports both CCXT and custom broker connectors
 *
 * Memory Profile:
 * - Before: 100 users × 3 exchanges × hourly = 7,200 instances/day (~3.6GB peak)
 * - After: ~300 cached instances max (~150MB), reused across snapshots
 *
 * TTL Strategy:
 * - Default: 1 hour (matches typical sync interval)
 * - Auto-cleanup every 10 minutes
 * - LRU eviction if cache exceeds max size
 */
@injectable()
export class UniversalConnectorCacheService {
  private cache = new Map<string, CachedConnector>();
  private stats: CacheStats = {
    hits: 0,
    misses: 0,
    evictions: 0,
    currentSize: 0,
    totalMemoryMB: 0,
  };

  // Configuration
  private readonly DEFAULT_TTL_MS = 60 * 60 * 1000; // 1 hour
  private readonly MAX_CACHE_SIZE = 500; // Max 500 cached connectors
  private readonly CLEANUP_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes
  private readonly ESTIMATED_CONNECTOR_SIZE_KB = 500; // ~500KB per instance

  private cleanupTimer: NodeJS.Timeout | null = null;

  constructor() {
    this.startCleanupTimer();
    logger.info('Universal Connector Cache initialized', {
      ttl: `${this.DEFAULT_TTL_MS / 1000 / 60}min`,
      maxSize: this.MAX_CACHE_SIZE,
      cleanupInterval: `${this.CLEANUP_INTERVAL_MS / 1000 / 60}min`,
    });
  }

  /**
   * Get or create a connector instance (CCXT, IBKR, Alpaca, etc.)
   *
   * @param exchange - Exchange ID (e.g., 'binanceusdm', 'bitget', 'ibkr', 'alpaca')
   * @param credentials - Exchange API credentials
   * @param ttlMs - Optional custom TTL in milliseconds
   * @returns Cached or new connector instance
   */
  getOrCreate(
    exchange: string,
    credentials: ExchangeCredentials,
    ttlMs?: number
  ): IExchangeConnector {
    const cacheKey = this.generateCacheKey(exchange, credentials);
    const now = Date.now();

    // Check cache
    const cached = this.cache.get(cacheKey);

    if (cached && cached.expires > now) {
      // Cache hit
      this.stats.hits++;
      cached.lastAccessed = now;
      cached.accessCount++;

      logger.debug('Connector cache HIT', {
        exchange,
        exchangeType: cached.exchangeType,
        userUid: credentials.userUid,
        age: Math.round((now - cached.createdAt) / 1000) + 's',
        accessCount: cached.accessCount,
      });

      return cached.connector;
    }

    // Cache miss - create new instance using ExchangeConnectorFactory
    this.stats.misses++;

    logger.debug('Connector cache MISS', {
      exchange,
      userUid: credentials.userUid,
      reason: cached ? 'expired' : 'not-found',
    });

    // Use ExchangeConnectorFactory to create the appropriate connector type
    const connector = ExchangeConnectorFactory.create(credentials);
    const exchangeType = ExchangeConnectorFactory.isCryptoExchange(exchange)
      ? 'ccxt'
      : 'custom-broker';
    const ttl = ttlMs || this.DEFAULT_TTL_MS;

    // Store in cache
    this.cache.set(cacheKey, {
      connector,
      expires: now + ttl,
      createdAt: now,
      lastAccessed: now,
      accessCount: 1,
      exchangeType,
    });

    // Enforce max cache size (LRU eviction)
    if (this.cache.size > this.MAX_CACHE_SIZE) {
      this.evictLRU();
    }

    // Update stats
    this.stats.currentSize = this.cache.size;
    this.stats.totalMemoryMB =
      (this.cache.size * this.ESTIMATED_CONNECTOR_SIZE_KB) / 1024;

    logger.info('Connector created and cached', {
      exchange,
      exchangeType,
      userUid: credentials.userUid,
      cacheSize: this.cache.size,
      ttl: `${ttl / 1000 / 60}min`,
    });

    return connector;
  }

  /**
   * Generate cache key from exchange + credentials
   * Uses hash of credentials to avoid storing sensitive data in keys
   */
  private generateCacheKey(
    exchange: string,
    credentials: ExchangeCredentials
  ): string {
    const credHash = crypto
      .createHash('sha256')
      .update(JSON.stringify({
        apiKey: credentials.apiKey,
        apiSecret: credentials.apiSecret,
        passphrase: credentials.passphrase,
      }))
      .digest('hex')
      .substring(0, 16);

    return `${exchange}:${credentials.userUid}:${credHash}`;
  }

  /**
   * Evict least recently used connector (LRU)
   */
  private evictLRU(): void {
    let oldestKey: string | null = null;
    let oldestAccess = Infinity;

    for (const [key, value] of this.cache.entries()) {
      if (value.lastAccessed < oldestAccess) {
        oldestAccess = value.lastAccessed;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
      this.stats.evictions++;
      logger.debug('LRU eviction', {
        key: oldestKey.substring(0, 30) + '...',
        age: Math.round((Date.now() - oldestAccess) / 1000) + 's',
      });
    }
  }

  /**
   * Start periodic cleanup timer
   */
  private startCleanupTimer(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanupExpired();
    }, this.CLEANUP_INTERVAL_MS);

    // Prevent timer from keeping process alive
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Clean up expired connectors
   */
  private cleanupExpired(): void {
    const now = Date.now();
    let removedCount = 0;

    for (const [key, value] of this.cache.entries()) {
      if (value.expires <= now) {
        this.cache.delete(key);
        removedCount++;
      }
    }

    if (removedCount > 0) {
      this.stats.currentSize = this.cache.size;
      this.stats.totalMemoryMB =
        (this.cache.size * this.ESTIMATED_CONNECTOR_SIZE_KB) / 1024;

      logger.info('Cache cleanup completed', {
        removed: removedCount,
        remaining: this.cache.size,
      });
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    return {
      ...this.stats,
      currentSize: this.cache.size,
      totalMemoryMB:
        (this.cache.size * this.ESTIMATED_CONNECTOR_SIZE_KB) / 1024,
    };
  }

  /**
   * Clear entire cache (useful for testing)
   */
  clear(): void {
    const size = this.cache.size;
    this.cache.clear();
    this.stats.currentSize = 0;
    this.stats.totalMemoryMB = 0;

    logger.info('Cache cleared', { removedCount: size });
  }

  /**
   * Shutdown - stop cleanup timer
   */
  shutdown(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.clear();
    logger.info('Universal Connector Cache shutdown');
  }
}
