FROM golang:1.26-alpine AS builder

# Install git and ca-certificates (required for fetching dependencies and HTTPS)
RUN apk update && apk add --no-cache git ca-certificates tzdata

# Create an unprivileged user (appuser) for execution
ENV USER=appuser
ENV UID=10001
RUN adduser \    
    --disabled-password \    
    --gecos "" \    
    --home "/nonexistent" \    
    --shell "/sbin/nologin" \    
    --no-create-home \    
    --uid "${UID}" \    
    "${USER}"

WORKDIR /build

# Cache dependencies first for faster builds
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build a statically linked binary. 
# CGO_ENABLED=0 ensures no external C libraries are required.
# -ldflags="-w -s" strips debug information to reduce binary size and hinder reverse engineering.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /go/bin/gateway ./cmd/api


FROM scratch

# Import the timezone data and CA certificates from the builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Import the unprivileged user from the builder
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy the hardened binary
COPY --from=builder /go/bin/gateway /gateway

# Enforce execution as the unprivileged user
USER appuser:appuser

# Expose the API port
EXPOSE 8080

# Run the binary
ENTRYPOINT ["/gateway"]