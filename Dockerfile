# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags '-extldflags "-static" -s -w' \
    -o brakebear \
    cmd/brakebear/main.go

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    iproute2 \
    iptables \
    docker-cli \
    tzdata \
    && rm -rf /var/cache/apk/*

# Create directories
RUN mkdir -p /etc/brakebear

# Copy binary from builder
COPY --from=builder /app/brakebear /usr/local/bin/brakebear

# Set permissions
RUN chmod +x /usr/local/bin/brakebear

# Set default configuration path
ENV BRAKEBEAR_CONFIG=/etc/brakebear/brakebear.yaml

WORKDIR /etc/brakebear

# Note: This container needs to run with elevated privileges and access to host network
# Run as root since network operations require elevated privileges
USER root

# Default command
ENTRYPOINT ["/usr/local/bin/brakebear"]
CMD ["run", "--config", "/etc/brakebear/brakebear.yaml"]
