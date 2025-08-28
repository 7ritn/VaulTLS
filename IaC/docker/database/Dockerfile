# PostgreSQL with VaulTLS optimizations
FROM postgres:16-alpine

# Install additional tools
RUN apk add --no-cache \
    curl \
    postgresql-contrib \
    && rm -rf /var/cache/apk/*

# Copy initialization scripts
COPY IaC/docker/database/init/ /docker-entrypoint-initdb.d/

# Copy configuration files
COPY IaC/docker/database/postgresql.conf /etc/postgresql/postgresql.conf
COPY IaC/docker/database/pg_hba.conf /etc/postgresql/pg_hba.conf

# Create directories for data and logs
RUN mkdir -p /var/lib/postgresql/data /var/log/postgresql && \
    chown -R postgres:postgres /var/lib/postgresql /var/log/postgresql

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD pg_isready -U ${POSTGRES_USER:-vaultls} -d ${POSTGRES_DB:-vaultls} || exit 1

# Environment variables with defaults
ENV POSTGRES_DB=vaultls
ENV POSTGRES_USER=vaultls
ENV POSTGRES_PASSWORD=changeme
ENV PGDATA=/var/lib/postgresql/data

# Expose port
EXPOSE 5432

# Labels for metadata
LABEL maintainer="VaulTLS Team" \
      version="2.0.0" \
      description="VaulTLS Database - PostgreSQL with optimizations" \
      org.opencontainers.image.title="VaulTLS Database" \
      org.opencontainers.image.description="PostgreSQL database for VaulTLS" \
      org.opencontainers.image.vendor="VaulTLS" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.created="2024-01-01T00:00:00Z" \
      org.opencontainers.image.source="https://github.com/Grace-Solutions/VaulTLS" \
      org.opencontainers.image.documentation="https://github.com/Grace-Solutions/VaulTLS/blob/main/docs/"
