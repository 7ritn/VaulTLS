# Multi-stage build for Vue.js frontend
FROM node:20-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY frontend/package*.json ./

# Install dependencies
RUN npm ci --only=production --silent

# Copy source code
COPY frontend/ .

# Build the application
RUN npm run build

# Production stage
FROM nginx:1.25-alpine AS production

# Install security updates
RUN apk update && apk upgrade && apk add --no-cache \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S vaultls && \
    adduser -S vaultls -u 1001 -G vaultls

# Copy built application
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY IaC/docker/frontend/nginx.conf /etc/nginx/nginx.conf
COPY IaC/docker/frontend/default.conf /etc/nginx/conf.d/default.conf

# Copy security headers configuration
COPY IaC/docker/frontend/security-headers.conf /etc/nginx/conf.d/security-headers.conf

# Create nginx directories and set permissions
RUN mkdir -p /var/cache/nginx /var/log/nginx /var/run && \
    chown -R vaultls:vaultls /var/cache/nginx /var/log/nginx /var/run /usr/share/nginx/html && \
    chmod -R 755 /usr/share/nginx/html

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Switch to non-root user
USER vaultls

# Expose port
EXPOSE 3000

# Start nginx
CMD ["nginx", "-g", "daemon off;"]

# Labels for metadata
LABEL maintainer="VaulTLS Team" \
      version="2.0.0" \
      description="VaulTLS Frontend - Vue.js Application" \
      org.opencontainers.image.title="VaulTLS Frontend" \
      org.opencontainers.image.description="Enterprise Certificate Management Frontend" \
      org.opencontainers.image.vendor="VaulTLS" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.created="2024-01-01T00:00:00Z" \
      org.opencontainers.image.source="https://github.com/Grace-Solutions/VaulTLS" \
      org.opencontainers.image.documentation="https://github.com/Grace-Solutions/VaulTLS/blob/main/docs/"
