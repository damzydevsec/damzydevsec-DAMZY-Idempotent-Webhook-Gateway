# DAMZY Webhook Gateway 🛡

A high-performance, idempotent microservice designed to safely process payment gateway webhooks (e.g., Paystack, Stripe) and prevent duplicate crediting.

## ⚠️ The Problem
Payment gateways operate on an "at-least-once" delivery guarantee. Network latency or server timeouts often cause gateways to fire the same webhook multiple times. If processed synchronously without checks, this results in double-crediting user wallets—a critical financial vulnerability.

## 💡 The Solution
This microservice acts as an architectural shield:
1. Cryptographic Verification: Validates the HMAC signature to drop spoofed/malicious requests instantly.
2. Idempotency Locks (Redis): Caches the unique transaction_id. If a duplicate webhook arrives, it intercepts it and returns a 200 OK without triggering backend logic.
3. Asynchronous Queuing: Pushes valid payloads into a background queue, returning a fast response to the payment gateway.

## 🛠 Tech Stack
* Architecture: Microservice / API Gateway
* Backend: Go (Golang)
* Caching & Queuing: Redis
* Deployment: Docker Ready

## 🚀 Quick Start (Docker)
`bash
# Clone the repository
git clone [https://github.com/damzydevsec/DAMZY-Idempotent-Webhook-Gateway.git](https://github.com/damzydevsec/DAMZY-Idempotent-Webhook-Gateway.git)

# Spin up the Redis cache and Go API using Docker Compose
docker-compose up --build