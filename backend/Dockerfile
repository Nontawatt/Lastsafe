# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o lastsafe ./cmd/lastsafe

# Final stage
FROM alpine:3.19

RUN apk add --no-cache \
    ca-certificates \
    restic \
    rclone \
    fuse \
    tzdata

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/lastsafe .

# Create data directory
RUN mkdir -p /app/data

# Expose port
EXPOSE 8080

# Set environment variables
ENV GIN_MODE=release
ENV DATABASE_PATH=/app/data/lastsafe.db

# Run the application
CMD ["./lastsafe"]
