package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trackrecord/enclave/internal/connector"
)

const (
	defaultMaxSize      = 500
	defaultTTL          = 1 * time.Hour
	defaultCleanupEvery = 10 * time.Minute
)

// ConnectorCache is an LRU cache for exchange connector instances.
type ConnectorCache struct {
	maxSize int
	ttl     time.Duration
	entries map[string]*cacheEntry
	mu      sync.RWMutex
	stopCh  chan struct{}

	hits      atomic.Int64
	misses    atomic.Int64
	evictions atomic.Int64
}

type cacheEntry struct {
	conn      connector.Connector
	createdAt time.Time
	lastUsed  time.Time
}

// CacheStats holds cache performance statistics.
type CacheStats struct {
	Hits      int64 `json:"hits"`
	Misses    int64 `json:"misses"`
	Evictions int64 `json:"evictions"`
	Size      int   `json:"size"`
}

// NewConnectorCache creates a new connector cache.
func NewConnectorCache() *ConnectorCache {
	c := &ConnectorCache{
		maxSize: defaultMaxSize,
		ttl:     defaultTTL,
		entries: make(map[string]*cacheEntry),
		stopCh:  make(chan struct{}),
	}

	// Start periodic cleanup
	go c.cleanupLoop()

	return c
}

// Get retrieves a cached connector, or returns nil if not found/expired.
func (c *ConnectorCache) Get(exchange, userUID string, credsHash []byte) connector.Connector {
	key := c.buildKey(exchange, userUID, credsHash)

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil
	}

	if time.Since(entry.createdAt) > c.ttl {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		c.misses.Add(1)
		c.evictions.Add(1)
		return nil
	}

	c.mu.Lock()
	entry.lastUsed = time.Now()
	c.mu.Unlock()

	c.hits.Add(1)
	return entry.conn
}

// Put stores a connector in the cache.
func (c *ConnectorCache) Put(exchange, userUID string, credsHash []byte, conn connector.Connector) {
	key := c.buildKey(exchange, userUID, credsHash)
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict LRU if at capacity
	if len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	c.entries[key] = &cacheEntry{
		conn:      conn,
		createdAt: now,
		lastUsed:  now,
	}
}

// Stats returns current cache statistics.
func (c *ConnectorCache) Stats() CacheStats {
	c.mu.RLock()
	size := len(c.entries)
	c.mu.RUnlock()

	return CacheStats{
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Evictions: c.evictions.Load(),
		Size:      size,
	}
}

// Stop stops the cleanup goroutine.
func (c *ConnectorCache) Stop() {
	close(c.stopCh)
}

// HashCredentials creates a SHA-256 hash of credentials for cache key generation.
func HashCredentials(apiKey, apiSecret, passphrase string) []byte {
	h := sha256.New()
	h.Write([]byte(apiKey))
	h.Write([]byte(apiSecret))
	h.Write([]byte(passphrase))
	return h.Sum(nil)
}

func (c *ConnectorCache) buildKey(exchange, userUID string, credsHash []byte) string {
	return fmt.Sprintf("%s:%s:%s", exchange, userUID, hex.EncodeToString(credsHash[:8]))
}

func (c *ConnectorCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.lastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.lastUsed
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
		c.evictions.Add(1)
	}
}

func (c *ConnectorCache) cleanupLoop() {
	ticker := time.NewTicker(defaultCleanupEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCh:
			return
		}
	}
}

func (c *ConnectorCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.Sub(entry.createdAt) > c.ttl {
			delete(c.entries, key)
			c.evictions.Add(1)
		}
	}
}
