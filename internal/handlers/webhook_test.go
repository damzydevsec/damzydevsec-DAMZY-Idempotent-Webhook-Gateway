// Author: Damzyfortress
// Security and Idempotency test suite for the Webhook Controller.
package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/damzydevsec/DAMZY-Webhook-Gateway/internal/cache"
)

func setupTestRedis(t *testing.T) (*cache.Client, *miniredis.Miniredis) {
	// Spin up an in-memory Redis server for this specific test
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}

	// Connect our hardened cache client to the in-memory server
	cfg := cache.Config{
		Addr:       mr.Addr(),
		MaxRetries: 1,
	}

	client, err := cache.NewClient(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Failed to create cache client: %v", err)
	}

	return client, mr
}

func TestHandlePaymentWebhook_Idempotency(t *testing.T) {
	redisClient, mr := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.GracefulShutdown()

	handler := &WebhookHandler{
		Redis: redisClient,
	}

	validJSON := []byte(`{"event":"charge.success","data":{"id":"tx_enterprise_001"}}`)

	// The Initial Webhook (Should Queue) ---
	req1 := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(validJSON))
	rr1 := httptest.NewRecorder()

	handler.HandlePaymentWebhook(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("Request 1 failed: expected 200 OK, got %d", rr1.Code)
	}

	// Verify it actually hit the Redis Queue
	mr.FastForward(1 * time.Millisecond) // Allow miniredis to process
	queueItems, err := mr.List("webhook:queue:processing")
	if err != nil || len(queueItems) != 1 {
		t.Errorf("Request 1 failed: expected queue length of 1, got %d. Err: %v", len(queueItems), err)
	}

	// We simulate the exact same payload arriving 2 seconds later
	req2 := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(validJSON))
	rr2 := httptest.NewRecorder()

	handler.HandlePaymentWebhook(rr2, req2)

	// It must still return 200 OK to the gateway to acknowledge it
	if rr2.Code != http.StatusOK {
		t.Errorf("Request 2 failed: expected 200 OK, got %d", rr2.Code)
	}

	// The queue length MUST STILL BE 1. It should not have queued again.
	queueItems, _ = mr.List("webhook:queue:processing")
	if len(queueItems) != 1 {
		t.Errorf("Idempotency failure! Duplicate webhook was queued. Queue length: %d", len(queueItems))
	}
}

func TestHandlePaymentWebhook_MalformedPayloads(t *testing.T) {
	redisClient, mr := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.GracefulShutdown()

	handler := &WebhookHandler{Redis: redisClient}

	tests := []struct {
		name           string
		payload        []byte
		expectedStatus int
	}{
		{
			name:           "Failure: Invalid JSON format",
			payload:        []byte(`{"event":"charge.success", "data": {"id": `), // Truncated JSON
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			name:           "Failure: Missing Transaction ID",
			payload:        []byte(`{"event":"charge.success","data":{}}`),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Failure: Dangerous Characters in ID (Injection Attempt)",
			payload:        []byte(`{"event":"charge.success","data":{"id":"tx_123*&^DROP_TABLE"}}`),
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(tc.payload))
			rr := httptest.NewRecorder()

			handler.HandlePaymentWebhook(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("Test '%s' failed: expected status %d, got %d", tc.name, tc.expectedStatus, rr.Code)
			}
		})
	}
}
