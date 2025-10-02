# Multi-stage build for optimized production image
FROM rust:1.83-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/zkp

# Copy manifest files
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto/ ./proto/
COPY benches/ ./benches/

# Copy all source code
COPY src/ ./src/

# Build application
RUN cargo build --release --bin server --bin client

# Production stage
FROM debian:bookworm-slim

# Install CA certificates for HTTPS
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false zkpuser

# Create app directory
WORKDIR /app

# Copy binaries from builder stage
COPY --from=builder /usr/src/zkp/target/release/server /app/
COPY --from=builder /usr/src/zkp/target/release/client /app/

# Copy configuration
COPY config/ ./config/

# Set ownership
RUN chown -R zkpuser:zkpuser /app

# Switch to non-root user
USER zkpuser

# Expose port
EXPOSE 50051

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD timeout 3 bash -c '</dev/tcp/localhost/50051' || exit 1

# Default command
CMD ["./server"]