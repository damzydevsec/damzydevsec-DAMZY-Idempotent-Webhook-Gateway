// Author: Damzyfortress
// Package worker manages background processing of queued webhooks with zero data loss.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/damzydevsec/DAMZY-Webhook-Gateway/internal/cache"
	"github.com/go-redis/redis/v8"
)

const (
	QueueProcessing = "webhook:queue:processing"
	QueueInFlight   = "webhook:queue:inflight"
)

type Processor struct {
	redis *cache.Client
	wg    sync.WaitGroup
}

// NewProcessor initializes the background worker.
func NewProcessor(r *cache.Client) *Processor {
	return &Processor{
		redis: r,
	}
}

// Start launches the worker loop. It listens for OS context cancellation to shut down gracefully.
func (p *Processor) Start(ctx context.Context) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		slog.Info("Background worker started. Listening for incoming webhooks...")

		for {
			select {
			case <-ctx.Done():
				slog.Info("Worker received shutdown signal, halting processing loop.")
				return
			default:
				// BRPopLPush blocks for up to 2 seconds waiting for a payload.
				// If a payload arrives, it moves it to the InFlight queue atomically.
				payload, err := p.redis.Client().BRPopLPush(ctx, QueueProcessing, QueueInFlight, 2*time.Second).Result()

				if errors.Is(err, redis.Nil) {
					// Timeout reached, no new webhooks. Loop continues.
					continue
				} else if err != nil {
					// If the context is canceled during the block, exit cleanly.
					if errors.Is(err, context.Canceled) {
						return
					}
					slog.Error("Redis queue fetch failed", "error", err)
					time.Sleep(1 * time.Second) // Backoff on infrastructure error
					continue
				}

				// We successfully captured a payload.
				p.processPayload(ctx, payload)
			}
		}
	}()
}

// processPayload executes the actual business logic.
func (p *Processor) processPayload(ctx context.Context, payload string) {
	slog.Info("Worker executing business logic...", "payload_preview", payload[:min(len(payload), 50)])

	// Simulate heavy database operations (e.g., updating PostgreSQL wallet balance)
	time.Sleep(500 * time.Millisecond)

	// Once the business logic completes successfully, we remove it from the InFlight queue.
	// If the pod crashes before this line, the payload stays in InFlight for recovery.
	err := p.redis.Client().LRem(ctx, QueueInFlight, 1, payload).Err()
	if err != nil {
		slog.Error("CRITICAL: Failed to remove payload from InFlight queue", "error", err)
		return
	}

	slog.Info("Worker successfully processed and acknowledged webhook.")
}

// Stop waits for active processing to finish before allowing the container to exit.
func (p *Processor) Stop() {
	slog.Info("Waiting for active workers to complete in-flight tasks...")
	p.wg.Wait()
	slog.Info("All background workers halted cleanly.")
}

// min is a helper for safe string slicing in logs
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
