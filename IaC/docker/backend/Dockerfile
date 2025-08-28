# Multi-stage build for Rust backend
FROM rust:1.75-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY backend/Cargo.toml backend/Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf src

# Copy source code
COPY backend/src ./src
COPY backend/migrations ./migrations

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libsqlite3-0 \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -r vaultls && useradd -r -g vaultls vaultls

# Create application directory
RUN mkdir -p /app/data /app/logs /app/certs && \
    chown -R vaultls:vaultls /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/vaultls /app/vaultls

# Copy configuration files
COPY backend/config/ /app/config/

# Set permissions
RUN chmod +x /app/vaultls && \
    chown vaultls:vaultls /app/vaultls

# Switch to non-root user
USER vaultls

# Set working directory
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/api/server/health || exit 1

# Expose port
EXPOSE 8000

# Environment variables
ENV RUST_LOG=info
ENV VAULTLS_DATABASE_URL=sqlite:///app/data/vaultls.db
ENV VAULTLS_DATA_DIR=/app/data
ENV VAULTLS_LOG_DIR=/app/logs
ENV VAULTLS_CERT_DIR=/app/certs

# Start the application
CMD ["./vaultls"]

# Labels for metadata
LABEL maintainer="VaulTLS Team" \
      version="2.0.0" \
      description="VaulTLS Backend - Rust API Server" \
      org.opencontainers.image.title="VaulTLS Backend" \
      org.opencontainers.image.description="Enterprise Certificate Management API" \
      org.opencontainers.image.vendor="VaulTLS" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.created="2024-01-01T00:00:00Z" \
      org.opencontainers.image.source="https://github.com/Grace-Solutions/VaulTLS" \
      org.opencontainers.image.documentation="https://github.com/Grace-Solutions/VaulTLS/blob/main/docs/"
