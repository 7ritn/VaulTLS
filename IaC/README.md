# VaulTLS Infrastructure as Code (IaC)

This directory contains all the infrastructure configuration files for deploying VaulTLS in various environments.

## 📁 Directory Structure

```
IaC/
├── docker/                 # Docker configurations
│   ├── frontend/           # Frontend container
│   ├── backend/            # Backend container
│   └── database/           # Database container
├── docker-compose/         # Docker Compose configurations
│   ├── development.yml     # Development environment
│   ├── production.yml      # Production environment
│   └── testing.yml         # Testing environment
├── kubernetes/             # Kubernetes manifests
│   ├── base/               # Base configurations
│   ├── overlays/           # Environment-specific overlays
│   └── helm/               # Helm charts
├── scripts/                # Deployment and utility scripts
├── configs/                # Configuration templates
└── docs/                   # Infrastructure documentation
```

## 🚀 Quick Start

### Development Environment

```bash
# Start development environment
docker-compose -f docker-compose/development.yml up -d

# View logs
docker-compose -f docker-compose/development.yml logs -f

# Stop environment
docker-compose -f docker-compose/development.yml down
```

### Production Environment

```bash
# Build and deploy production
docker-compose -f docker-compose/production.yml up -d

# Scale services
docker-compose -f docker-compose/production.yml up -d --scale backend=3
```

## 🔧 Configuration

### Environment Variables

All environments support the following configuration options:

- **Database Configuration**: PostgreSQL/SQLite settings
- **Security Settings**: JWT secrets, encryption keys
- **Network Configuration**: Ports, domains, SSL settings
- **Feature Flags**: Enable/disable specific features
- **Monitoring**: Logging levels, metrics collection

### Secrets Management

- Development: `.env` files (not committed)
- Production: Kubernetes secrets or Docker secrets
- CI/CD: GitHub Actions secrets

## 📊 Monitoring & Observability

- **Health Checks**: Built-in health endpoints
- **Metrics**: Prometheus-compatible metrics
- **Logging**: Structured JSON logging
- **Tracing**: OpenTelemetry support

## 🔒 Security

- **Container Security**: Non-root users, minimal base images
- **Network Security**: Internal networks, firewall rules
- **Data Security**: Encrypted volumes, secure secrets
- **Access Control**: RBAC, service accounts

## 📖 Documentation

- [Docker Setup Guide](docs/docker-setup.md)
- [Kubernetes Deployment](docs/kubernetes-deployment.md)
- [Production Checklist](docs/production-checklist.md)
- [Troubleshooting Guide](docs/troubleshooting.md)
