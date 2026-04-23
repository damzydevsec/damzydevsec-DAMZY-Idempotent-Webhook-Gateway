// Author: Damzyfortress
// Package handlers manages secure, highly concurrent HTTP request processing.
package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/damzydevsec/DAMZY-Webhook-Gateway/internal/cache"
)

// WebhookPayload represents a strictly bounded extraction struct.
// We intentionally ignore fields we don't need to save CPU cycles during parsing.
type WebhookPayload struct {
	Event string `json:"event"`
	Data  struct {
		TransactionID string `json:"id"` // Adjust to match your gateway (e.g., reference, tx_ref)
	} `json:"data"`
}

type WebhookHandler struct {
	Redis *cache.Client
}

// txIDValidator ensures the ID only contains safe alphanumeric characters, hyphens, or underscores.
// It prevents Redis key injection and massive string allocations.
var txIDValidator = regexp.MustCompile(`^[a-zA-Z0-9_-]{5,100}$`)

// HandlePaymentWebhook processes the payload, guarantees idempotency, and queues for workers.
func (h *WebhookHandler) HandlePaymentWebhook(w http.ResponseWriter, r *http.Request) {
	//  Read the raw payload safely
	// (Guaranteed safe here because VerifyHMAC middleware enforces a 1MB MaxBytesReader)
	rawPayload, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("Failed to read payload bytes", "ip", r.RemoteAddr, "error", err)
		writeOpaqueError(w, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse strictly what we need
	var payload WebhookPayload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		slog.Warn("Malformed JSON payload received", "ip", r.RemoteAddr, "error", err)
		writeOpaqueError(w, http.StatusUnprocessableEntity)
		return
	}

	txID := payload.Data.TransactionID

	//  Sanitize and Validate the Transaction ID
	if !txIDValidator.MatchString(txID) {
		slog.Warn("Invalid transaction ID format detected",
			"ip", r.RemoteAddr,
			"txID_length", len(txID),
		)
		writeOpaqueError(w, http.StatusBadRequest)
		return
	}

	// Execute the Atomic Check-then-Set Idempotency Flow
	isNew, err := h.Redis.ProcessWebhook(r.Context(), txID, rawPayload)
	if err != nil {
		// Log the critical infrastructure error internally, but do NOT leak it.
		slog.Error("Redis idempotency transaction failed",
			"txID", txID,
			"event", payload.Event,
			"error", err,
		)

		// Return 500 so the gateway knows we failed and will retry later.
		writeOpaqueError(w, http.StatusInternalServerError)
		return
	}

	// Audit Logging based on Idempotency Result
	if !isNew {
		// Duplicate webhook intercepted and neutralized.
		// Log at debug/info level to prevent log-flooding during mass retries.
		slog.Info("Idempotency lock triggered: Duplicate webhook dropped", "txID", txID)
	} else {
		slog.Info("New webhook successfully verified and queued",
			"txID", txID,
			"event", payload.Event,
		)
	}

	//  Acknowledge Receipt
	// Regardless of whether it was new or duplicate, we return 200 OK to the gateway
	// so it considers the delivery successful and stops polling our infrastructure.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"success","message":"webhook acknowledged"}`))
}

// writeOpaqueError enforces strict boundary control on outgoing error messages.
// It ensures stack traces or infrastructure states are never leaked to the client.
func writeOpaqueError(w http.ResponseWriter, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)

	// Standardized, vague error mapping
	msg := "An error occurred"
	if statusCode == http.StatusBadRequest || statusCode == http.StatusUnprocessableEntity {
		msg = "Invalid request payload"
	} else if statusCode == http.StatusInternalServerError {
		msg = "Internal infrastructure error"
	}

	// Using a static JSON string is highly allocation-efficient for error paths
	response := `{"status":"error","message":"` + msg + `"}`
	_, _ = w.Write([]byte(response))
}
