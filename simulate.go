// Author: Damzyfortress
// Developer tool to simulate live Paystack/Stripe webhooks with valid cryptographic signatures.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

func main() {
	// The exact secret key your Docker container is using
	secretKey := "sk_test_damzy12345securekey"
	targetURL := "http://localhost:8080/api/v1/webhook"

	// The mock payload
	payload := []byte(`{"event":"charge.success","data":{"id":"tx_live_enterprise_999"}}`)

	// Generate the valid HMAC-SHA512 Signature
	mac := hmac.New(sha512.New, []byte(secretKey))
	mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))

	//  Construct the Request
	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		panic(err)
	}

	// Attach the required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-paystack-signature", signature)

	//  Fire the Webhook
	fmt.Println("Firing Webhook to DAMZY Gateway...")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	//  Read the Response
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Gateway Response Status: %s\n", resp.Status)
	fmt.Printf("Gateway Response Body: %s\n", string(body))
}
