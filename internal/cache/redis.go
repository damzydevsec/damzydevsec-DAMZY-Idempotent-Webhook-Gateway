// Author: Damzyfortress
// Package cache provides a highly available, secure, and atomic Redis interface.
package cache

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/go-redis/redis/v8"
)

// We use a Lua script to guarantee 100% atomicity.
// KEYS[1] = Lock Key, KEYS[2] = Queue Key
// ARGV[1] = Lock Value, ARGV[2] = TTL in seconds, ARGV[3] = Payload
const idempotencyScript = `
if redis.call("SET", KEYS[1], ARGV[1], "NX", "EX", ARGV[2]) then
 redis.call("LPUSH", KEYS[2], ARGV[3])
 return 1
else
 return 0
end
`

type Client struct {
	rdb    *redis.Client
	script *redis.Script
}

// Config struct allows for scalable environment-based configuration
type Config struct {
	Addr       string
	Password   string
	DB         int
	UseTLS     bool
	MaxRetries int
}

// NewClient initializes a hardened Redis connection pool with SRE best practices.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	opts := &redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,

		//  Connection Pooling
		PoolSize:     200, // Max concurrent connections
		MinIdleConns: 20,  // Keep warm connections ready for sudden traffic spikes
		IdleTimeout:  5 * time.Minute,
		PoolTimeout:  4 * time.Second, // Max time to wait for a free connection

		// Timeouts & Retries
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		MaxRetries:      cfg.MaxRetries,
		MinRetryBackoff: 8 * time.Millisecond,
		MaxRetryBackoff: 512 * time.Millisecond,
	}

	// Enable TLS for Zero Trust networks (AWS ElastiCache, etc.)
	if cfg.UseTLS {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			// In strict military-grade setups, you would load custom root CAs here
		}
	}

	rdb := redis.NewClient(opts)

	// Validate the connection instantly rather than failing at the first HTTP request
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if err := rdb.Ping(pingCtx).Err(); err != nil {
		// Log detailed network errors for rapid SRE debugging
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("redis connection timeout: %w", err)
		}
		return nil, fmt.Errorf("failed to connect to redis at %s: %w", cfg.Addr, err)
	}

	// Pre-load the Lua script into the client to avoid sending the script string every time
	script := redis.NewScript(idempotencyScript)

	slog.Info("Hardened Redis connection established",
		"addr", cfg.Addr,
		"tls_enabled", cfg.UseTLS,
		"pool_size", opts.PoolSize,
	)

	return &Client{
		rdb:    rdb,
		script: script,
	}, nil
}

// ProcessWebhook executes the Check-then-Set and Queue operation atomically.
// Returns true if the webhook was processed, false if it was rejected as a duplicate.
func (c *Client) ProcessWebhook(ctx context.Context, txID string, payload []byte) (bool, error) {
	lockKey := fmt.Sprintf("webhook:lock:v1:%s", txID)
	queueKey := "webhook:queue:processing"
	lockTTL := 86400 // 24 hours in seconds

	// Enforce strict bounded contexts on all outbound cache calls
	execCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Execute the Lua script.
	// We pass the keys and args. The script runs entirely on the Redis engine.
	result, err := c.script.Run(execCtx, c.rdb, []string{lockKey, queueKey}, "locked", lockTTL, payload).Result()

	if err != nil {
		// Differentiate between context timeouts (our fault) and Redis errors (infrastructure fault)
		if err == context.DeadlineExceeded {
			return false, fmt.Errorf("redis operation timed out: %w", err)
		}
		return false, fmt.Errorf("failed to execute atomic idempotency script: %w", err)
	}

	// The Lua script returns 1 if it successfully set the lock and pushed, 0 if the lock existed.
	success, ok := result.(int64)
	if !ok {
		return false, fmt.Errorf("unexpected return type from lua script: %v", result)
	}

	return success == 1, nil
}

// GracefulShutdown ensures all pending operations complete and connections close cleanly.
func (c *Client) GracefulShutdown() error {
	slog.Info("Closing Redis connection pool")
	return c.rdb.Close()
}

// Client returns the underlying Redis client for advanced queuing operations.
func (c *Client) Client() *redis.Client {
	return c.rdb
}
