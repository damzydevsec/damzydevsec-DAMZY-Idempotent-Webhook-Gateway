// Author: Damzyfortress
// Security test suite for the HMAC verification middleware.
package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSecretKey = "test_super_secret_key_12345"

// generateValidSignature is a helper to mock the payment gateway's hashing process.
func generateValidSignature(payload []byte, secret string) string {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyHMAC(t *testing.T) {
	// A dummy downstream handler that returns 200 OK if the middleware lets the request pass.
	mockNextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Initialize the middleware with our test secret.
	middlewareUnderTest := VerifyHMAC(testSecretKey)(mockNextHandler)

	validPayload := []byte(`{"event":"charge.success","data":{"id":"tx_123"}}`)
	validSig := generateValidSignature(validPayload, testSecretKey)

	// We use table-driven tests to easily simulate multiple attack vectors.
	tests := []struct {
		name           string
		payload        []byte
		signature      string
		expectedStatus int
	}{
		{
			name:           "Success: Valid Payload and Signature",
			payload:        validPayload,
			signature:      validSig,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Failure: Missing Signature Header",
			payload:        validPayload,
			signature:      "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Failure: Invalid Hex in Signature",
			payload:        validPayload,
			signature:      "not-a-valid-hex-string",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Failure: Signature Length Mismatch",
			payload:        validPayload,
			signature:      "deadbeef", // Valid hex, but way too short for SHA512
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Failure: Incorrect Signature (Tampered Payload)",
			payload:        []byte(`{"event":"charge.success","data":{"id":"tx_999"}}`), // Changed ID
			signature:      validSig,                                                    // Using signature for tx_123
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Failure: DoS Memory Exhaustion Attack",
			payload:        bytes.Repeat([]byte("A"), MaxPayloadSize+1), // 1 byte over the 1MB limit
			signature:      generateValidSignature(bytes.Repeat([]byte("A"), MaxPayloadSize+1), testSecretKey),
			expectedStatus: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Construct the mock HTTP request
			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(tc.payload))

			// Attach the signature if the test case dictates it
			if tc.signature != "" {
				req.Header.Set("x-paystack-signature", tc.signature)
			}

			// Record the HTTP response
			rr := httptest.NewRecorder()

			// Execute the middleware
			middlewareUnderTest.ServeHTTP(rr, req)

			// Assert the result matches our security expectations
			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("Test '%s' failed: handler returned wrong status code: got %v want %v",
					tc.name, status, tc.expectedStatus)
			}

			// Specific check for the DoS protection
			if tc.expectedStatus == http.StatusRequestEntityTooLarge {
				body, _ := io.ReadAll(rr.Body)
				if !strings.Contains(string(body), "Payload Too Large") {
					t.Errorf("Test '%s' failed: expected specific DoS error message, got: %s", tc.name, string(body))
				}
			}
		})
	}
}
