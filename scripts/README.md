# VaulTLS Scripts

This directory contains utility scripts for development, deployment, and maintenance of VaulTLS.

## Script Categories

### Development Scripts
- `dev/` - Development and testing scripts
- `dev/setup-dev-env.ps1` - Set up development environment
- `dev/run-tests.ps1` - Run test suites
- `dev/lint-code.ps1` - Code linting and formatting
- `dev/generate-certs.ps1` - Generate test certificates

### Database Scripts
- `database/` - Database management scripts
- `database/migrate.ps1` - Run database migrations
- `database/backup.ps1` - Backup database
- `database/restore.ps1` - Restore database from backup
- `database/seed-data.ps1` - Seed test data

### Deployment Scripts
- `deployment/` - Deployment and infrastructure scripts
- `deployment/build.ps1` - Build application for deployment
- `deployment/deploy.ps1` - Deploy application
- `deployment/health-check.ps1` - Health check script
- `deployment/rollback.ps1` - Rollback deployment

### Maintenance Scripts
- `maintenance/` - Maintenance and cleanup scripts
- `maintenance/cleanup-expired-certs.ps1` - Clean up expired certificates
- `maintenance/rotate-logs.ps1` - Log rotation
- `maintenance/backup-certs.ps1` - Backup certificate store
- `maintenance/update-dependencies.ps1` - Update dependencies

### Utility Scripts
- `utils/` - General utility scripts
- `utils/generate-token.ps1` - Generate API tokens
- `utils/validate-config.ps1` - Validate configuration
- `utils/export-data.ps1` - Export data for migration
- `utils/import-data.ps1` - Import data from migration

## Script Standards

### PowerShell Scripts
- Use PowerShell 7+ compatible syntax
- Include proper error handling with try/catch blocks
- Add parameter validation and help documentation
- Use Write-Progress for long-running operations
- Follow PowerShell naming conventions (Verb-Noun)
- Include examples in comment-based help

### General Guidelines
- All scripts should be idempotent where possible
- Include logging for important operations
- Validate prerequisites before execution
- Provide clear error messages
- Include rollback procedures for destructive operations
- Test scripts in development environment first

## Usage Examples

```powershell
# Set up development environment
.\scripts\dev\setup-dev-env.ps1

# Run database migrations
.\scripts\database\migrate.ps1 -Environment Development

# Deploy to staging
.\scripts\deployment\deploy.ps1 -Environment Staging -Version "2025.08.27.1041"

# Generate test certificates
.\scripts\dev\generate-certs.ps1 -Count 10 -Type Client
```

## Contributing Scripts

When adding new scripts:

1. Choose the appropriate category directory
2. Follow the naming conventions
3. Include proper documentation and help
4. Test thoroughly before committing
5. Update this README if adding new categories
6. Ensure scripts work on both Windows and cross-platform where applicable
