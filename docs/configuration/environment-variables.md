# VaulTLS Environment Variables Configuration

This document describes all environment variables used to configure VaulTLS behavior.

## 🔐 API Documentation Security

### `VAULTLS_API_DOCS_ENABLED`
- **Type**: Boolean (`true`/`false`)
- **Default**: `true`
- **Description**: Controls whether API documentation endpoints are available
- **Security Impact**: When set to `false`, completely disables all API documentation endpoints

```bash
# Disable API documentation entirely
VAULTLS_API_DOCS_ENABLED=false

# Enable API documentation (default)
VAULTLS_API_DOCS_ENABLED=true
```

### `VAULTLS_API_DOCS_REQUIRE_AUTH`
- **Type**: Boolean (`true`/`false`)
- **Default**: `false`
- **Description**: Controls whether API documentation requires Bearer token authentication
- **Security Impact**: When set to `true`, requires valid Bearer token to access documentation

```bash
# Require authentication for API docs
VAULTLS_API_DOCS_REQUIRE_AUTH=true

# Allow public access to API docs (default)
VAULTLS_API_DOCS_REQUIRE_AUTH=false
```

## 📊 Reporting and History Configuration

### `VAULTLS_AUDIT_RETENTION_DAYS`
- **Type**: Integer
- **Default**: `2555` (7 years)
- **Description**: Number of days to retain audit events for compliance
- **Range**: `30` to `3650` (1 month to 10 years)

```bash
# Retain audit events for 5 years
VAULTLS_AUDIT_RETENTION_DAYS=1825

# Retain audit events for 1 year (minimum recommended)
VAULTLS_AUDIT_RETENTION_DAYS=365
```

### `VAULTLS_AUDIT_EXPORT_MAX_RECORDS`
- **Type**: Integer
- **Default**: `100000`
- **Description**: Maximum number of audit records that can be exported in a single request
- **Range**: `1000` to `1000000`

```bash
# Allow large exports for compliance reporting
VAULTLS_AUDIT_EXPORT_MAX_RECORDS=500000

# Limit exports for performance
VAULTLS_AUDIT_EXPORT_MAX_RECORDS=50000
```

### `VAULTLS_CERTIFICATE_HISTORY_ENABLED`
- **Type**: Boolean (`true`/`false`)
- **Default**: `true`
- **Description**: Controls whether certificate history tracking is enabled
- **Impact**: When disabled, reduces database storage but limits audit capabilities

```bash
# Enable full certificate history tracking (recommended)
VAULTLS_CERTIFICATE_HISTORY_ENABLED=true

# Disable history tracking to save storage
VAULTLS_CERTIFICATE_HISTORY_ENABLED=false
```

## 🔒 Security Configuration

### `VAULTLS_API_SECRET`
- **Type**: String (32+ characters)
- **Required**: Yes
- **Description**: Secret key for Bearer token HMAC signing
- **Security**: Must be cryptographically secure and unique per environment

```bash
# Production example (use a secure random string)
VAULTLS_API_SECRET="your-secure-32-character-secret-key-here-123456789"
```

### `VAULTLS_TOKEN_EXPIRY_HOURS`
- **Type**: Integer
- **Default**: `8760` (1 year)
- **Description**: Default expiry time for Bearer tokens in hours
- **Range**: `1` to `87600` (1 hour to 10 years)

```bash
# Tokens expire after 30 days
VAULTLS_TOKEN_EXPIRY_HOURS=720

# Tokens expire after 1 year (default)
VAULTLS_TOKEN_EXPIRY_HOURS=8760
```

## 🗄️ Database Configuration

### `VAULTLS_DATABASE_URL`
- **Type**: String (SQLite path)
- **Default**: `./vaultls.db`
- **Description**: Path to SQLite database file

```bash
# Production database
VAULTLS_DATABASE_URL="/var/lib/vaultls/production.db"

# Development database
VAULTLS_DATABASE_URL="./dev.db"

# In-memory database (testing only)
VAULTLS_DATABASE_URL=":memory:"
```

## 📧 Email Configuration

### `VAULTLS_MAIL_HOST`
- **Type**: String (hostname/IP)
- **Required**: Yes
- **Description**: SMTP server hostname

### `VAULTLS_MAIL_PORT`
- **Type**: Integer
- **Default**: `587`
- **Description**: SMTP server port

### `VAULTLS_MAIL_FROM`
- **Type**: String (email address)
- **Required**: Yes
- **Description**: From address for system emails

```bash
# Production SMTP configuration
VAULTLS_MAIL_HOST="smtp.company.com"
VAULTLS_MAIL_PORT=587
VAULTLS_MAIL_FROM="vaultls@company.com"
```

## 🚀 Performance Configuration

### `VAULTLS_RATE_LIMIT_PER_MINUTE`
- **Type**: Integer
- **Default**: `1000`
- **Description**: Default rate limit for Bearer tokens (requests per minute)
- **Range**: `10` to `10000`

```bash
# Conservative rate limiting
VAULTLS_RATE_LIMIT_PER_MINUTE=100

# High-performance rate limiting
VAULTLS_RATE_LIMIT_PER_MINUTE=5000
```

### `VAULTLS_SEARCH_MAX_RESULTS`
- **Type**: Integer
- **Default**: `10000`
- **Description**: Maximum number of results returned by search endpoints
- **Range**: `100` to `100000`

```bash
# Limit search results for performance
VAULTLS_SEARCH_MAX_RESULTS=5000
```

## 📝 Logging Configuration

### `VAULTLS_LOG_LEVEL`
- **Type**: String
- **Default**: `info`
- **Options**: `trace`, `debug`, `info`, `warn`, `error`
- **Description**: Logging verbosity level

```bash
# Debug logging for development
VAULTLS_LOG_LEVEL=debug

# Production logging
VAULTLS_LOG_LEVEL=info

# Minimal logging
VAULTLS_LOG_LEVEL=warn
```

## 🔧 Example Configurations

### Development Environment
```bash
VAULTLS_API_DOCS_ENABLED=true
VAULTLS_API_DOCS_REQUIRE_AUTH=false
VAULTLS_LOG_LEVEL=debug
VAULTLS_DATABASE_URL="./dev.db"
VAULTLS_API_SECRET="dev-secret-key-32-characters-long-123"
VAULTLS_MAIL_HOST="localhost"
VAULTLS_MAIL_PORT=1025
VAULTLS_MAIL_FROM="dev@vaultls.local"
```

### Production Environment
```bash
VAULTLS_API_DOCS_ENABLED=false
VAULTLS_API_DOCS_REQUIRE_AUTH=true
VAULTLS_LOG_LEVEL=info
VAULTLS_DATABASE_URL="/var/lib/vaultls/production.db"
VAULTLS_API_SECRET="prod-secure-random-secret-key-32-chars-min"
VAULTLS_AUDIT_RETENTION_DAYS=2555
VAULTLS_RATE_LIMIT_PER_MINUTE=1000
VAULTLS_MAIL_HOST="smtp.company.com"
VAULTLS_MAIL_PORT=587
VAULTLS_MAIL_FROM="vaultls@company.com"
```

### High-Security Environment
```bash
VAULTLS_API_DOCS_ENABLED=false
VAULTLS_API_DOCS_REQUIRE_AUTH=true
VAULTLS_TOKEN_EXPIRY_HOURS=24
VAULTLS_RATE_LIMIT_PER_MINUTE=100
VAULTLS_AUDIT_RETENTION_DAYS=3650
VAULTLS_LOG_LEVEL=info
```

## 🔍 Configuration Validation

VaulTLS validates all environment variables on startup and will:
- Use secure defaults for missing optional variables
- Fail to start if required variables are missing
- Log warnings for potentially insecure configurations
- Provide helpful error messages for invalid values

Check the startup logs for configuration validation results.
