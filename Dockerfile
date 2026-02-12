# Multi-stage build for cowboy
# Stage 1: Build the Go binary
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o cowboy main.go

# Stage 2: Create minimal runtime image
FROM alpine:3.21

# Install ca-certificates for HTTPS support (needed for -url flag)
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/cowboy /app/cowboy

# Run as non-root user for security
RUN adduser -D -u 1000 cowboy && \
    chown cowboy:cowboy /app/cowboy
USER cowboy

ENTRYPOINT ["/app/cowboy"]
