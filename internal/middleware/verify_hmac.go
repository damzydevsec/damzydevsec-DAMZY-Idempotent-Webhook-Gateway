// Author: Damzyfortress
// Package middleware provides zero-trust security and pre-processing intercepts.
package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
)

const (
	// MaxPayloadSize protects the pod against memory exhaustion DoS attacks.
	// Payment webhooks are typically small JSON payloads (< 100KB).
	// A hard limit of 1MB ensures predictability in memory consumption.
	MaxPayloadSize = 1 << 20 // 1 MB
)

// VerifyHMAC enforces cryptographic verification of incoming payloads.
// It uses a closure to initialize the secret key once, preventing os.Getenv calls on every request.
func VerifyHMAC(secretKey string) func(http.Handler) http.Handler {
	// Pre-compute the secret key to a byte slice during server initialization.
	keyBytes := []byte(secretKey)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract Signature Header
			sigHeader := r.Header.Get("x-paystack-signature")
			if sigHeader == "" {
				slog.Warn("HMAC verification failed: missing signature header", "ip", r.RemoteAddr)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			//  Protect against DoS with http.MaxBytesReader
			// This drops the connection immediately if the payload exceeds 1MB.
			r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadSize)

			//  Read the bounded payload securely
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				// Differentiate between a standard read error and a DoS attempt
				slog.Warn("HMAC verification failed: payload read error or size exceeded", "ip", r.RemoteAddr, "error", err)
				http.Error(w, "Payload Too Large or Malformed", http.StatusRequestEntityTooLarge)
				return
			}

			//  Restore the request body using bytes.NewReader (more allocation-efficient than NewBuffer)
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			//  Compute the expected HMAC-SHA512
			mac := hmac.New(sha512.New, keyBytes)
			mac.Write(bodyBytes)
			expectedMAC := mac.Sum(nil)

			//  Decode the incoming hex signature to raw bytes.
			// This prevents string-comparison vulnerabilities and normalizes the data.
			providedMAC, err := hex.DecodeString(sigHeader)
			if err != nil {
				slog.Warn("HMAC verification failed: invalid hex encoding in signature", "ip", r.RemoteAddr)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			//  Prevent length-leak attacks and out-of-bounds panics
			// crypto/subtle panics or leaks timing data if the slices are different lengths.
			if len(providedMAC) != len(expectedMAC) {
				slog.Warn("HMAC verification failed: signature length mismatch", "ip", r.RemoteAddr)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			//  Constant-Time Comparison
			// This evaluates the entire byte slice regardless of where the first mismatch occurs,
			// defeating timing-based cryptographic extraction attacks.
			if subtle.ConstantTimeCompare(providedMAC, expectedMAC) != 1 {
				slog.Warn("HMAC verification failed: signature mismatch", "ip", r.RemoteAddr)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Security checks passed. Hand off to the downstream controller.
			next.ServeHTTP(w, r)
		})
	}
}
