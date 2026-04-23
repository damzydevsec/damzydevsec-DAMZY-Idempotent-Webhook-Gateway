// Author: Damzyfortress
// Application entrypoint for DAMZY-Idempotent-Webhook-Gateway.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/damzydevsec/DAMZY-Webhook-Gateway/internal/cache"
	"github.com/damzydevsec/DAMZY-Webhook-Gateway/internal/handlers"
	"github.com/damzydevsec/DAMZY-Webhook-Gateway/internal/middleware"
	"github.com/damzydevsec/DAMZY-Webhook-Gateway/internal/worker" // Imported the worker
	"github.com/joho/godotenv"
)

func main() {
	// Initialize Structured Logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	//  Load Environment Variables
	if err := godotenv.Load(); err != nil {
		slog.Warn("No .env file found; relying on system environment variables")
	}

	//  Fail-Fast Configuration Validation
	secretKey := os.Getenv("PAYMENT_SECRET_KEY")
	if secretKey == "" {
		slog.Error("FATAL: PAYMENT_SECRET_KEY is required but missing")
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		slog.Error("FATAL: REDIS_ADDR is required but missing")
		os.Exit(1)
	}

	useTLS, _ := strconv.ParseBool(os.Getenv("REDIS_USE_TLS"))

	//  Initialize Hardened Infrastructure (Redis)
	ctx := context.Background()
	redisClient, err := cache.NewClient(ctx, cache.Config{
		Addr:       redisAddr,
		Password:   os.Getenv("REDIS_PASSWORD"),
		DB:         0,
		UseTLS:     useTLS,
		MaxRetries: 3,
	})
	if err != nil {
		slog.Error("FATAL: Failed to initialize Redis", "error", err)
		os.Exit(1)
	}

	//  Initialize Controllers
	webhookHandler := &handlers.WebhookHandler{
		Redis: redisClient,
	}

	//  Initialize and Start the Background Worker
	workerCtx, workerCancel := context.WithCancel(context.Background())
	payloadProcessor := worker.NewProcessor(redisClient)
	payloadProcessor.Start(workerCtx)

	//  Setup Isolated Routing
	mux := http.NewServeMux()
	webhookRoute := middleware.VerifyHMAC(secretKey)(http.HandlerFunc(webhookHandler.HandlePaymentWebhook))
	mux.Handle("POST /api/v1/webhook", webhookRoute)

	//  Configure Hardened HTTP Server
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start Server in a Goroutine
	go func() {
		slog.Info("Gateway active and listening", "port", port, "tls_redis", useTLS)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server encountered a fatal error", "error", err)
			os.Exit(1)
		}
	}()

	//  Coordinate Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	slog.Info("Termination signal received, initiating graceful shutdown...", "signal", sig.String())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Safely close the HTTP Server first to stop accepting new webhooks
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP server shutdown forced", "error", err)
	} else {
		slog.Info("HTTP server shutdown successfully")
	}

	// Tell the worker to stop pulling new jobs
	workerCancel()
	// Block until the worker finishes its current in-flight job
	payloadProcessor.Stop()

	// Safely close the Redis connection pool
	if err := redisClient.GracefulShutdown(); err != nil {
		slog.Error("Error closing Redis connection", "error", err)
	} else {
		slog.Info("Redis connections closed successfully")
	}

	slog.Info("Gateway shutdown complete")
}
