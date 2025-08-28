# VaulTLS API Migration Guide

This guide helps you migrate from the legacy session-based API to the modern Bearer token API.

## Overview

VaulTLS 2.0 introduces a unified API architecture with:
- **Bearer Token Authentication** - Secure, scope-based API access
- **Centralized Endpoint Management** - Consistent API structure
- **Enhanced Security** - Granular permissions and audit logging
- **Improved Performance** - Optimized for automation and integration

## Migration Timeline

| Phase | Date | Status | Description |
|-------|------|--------|-------------|
| **Deprecation Notice** | 2024-01-01 | ⚠️ Active | Legacy endpoints marked as deprecated |
| **Migration Period** | 2024-01-01 to 2024-06-01 | 🔄 Current | Both APIs available with warnings |
| **Legacy Removal** | 2024-06-01 | 🚫 Planned | Legacy endpoints will be removed |

## Quick Migration Checklist

- [ ] Create Bearer API tokens with appropriate scopes
- [ ] Update authentication from session cookies to Bearer tokens
- [ ] Replace legacy endpoints with modern equivalents
- [ ] Update request/response handling for new formats
- [ ] Test all integrations with new API
- [ ] Update documentation and scripts

## Authentication Migration

### Before (Session-based)
```bash
# Login to get session cookie
curl -X POST https://vaultls.company.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@company.com", "password": "password"}' \
  -c cookies.txt

# Use session cookie for API calls
curl https://vaultls.company.com/api/certificates \
  -b cookies.txt
```

### After (Bearer Token)
```bash
# Create API token (one-time setup)
curl -X POST https://vaultls.company.com/api/tokens \
  -H "Authorization: Bearer admin-session-token" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Migration Token",
    "scopes": ["cert.read", "cert.write", "ca.read"],
    "expires_at": null
  }'

# Use Bearer token for API calls
curl https://vaultls.company.com/api/certificates/search \
  -H "Authorization: Bearer vlt_abc123_token-value" \
  -H "Content-Type: application/json" \
  -d '{"page": 1, "per_page": 50}'
```

## Endpoint Migrations

### 1. Certificate Listing

#### Before (Legacy)
```bash
GET /api/certificates
```

#### After (Modern)
```bash
POST /api/certificates/search
Content-Type: application/json

{
  "page": 1,
  "per_page": 50,
  "filters": [],
  "sort": [{"field": "created_at", "direction": "desc"}]
}
```

**Breaking Changes:**
- Requires Bearer token with `cert.read` scope
- POST request instead of GET
- Pagination and filtering support
- Enhanced response format

### 2. Certificate Creation

#### Before (Legacy)
```bash
POST /api/certificates
Content-Type: application/json

{
  "name": "example.com",
  "user_id": 1,
  "certificate_type": "Server",
  "validity_years": 1
}
```

#### After (Modern)
```bash
POST /api/certificates
Content-Type: application/json

{
  "name": "example.com",
  "user_id": 1,
  "certificate_type": "Server",
  "validity_years": 1,
  "ca_selection": "auto",
  "profile_id": "server-profile",
  "sans": "example.com,www.example.com"
}
```

**Breaking Changes:**
- Requires Bearer token with `cert.write` scope
- Enhanced request format with CA selection
- Profile-based certificate creation
- SAN support in request

### 3. Certificate Download

#### Before (Legacy)
```bash
GET /api/certificates/{id}/download
```

#### After (Modern)
```bash
POST /api/certificates/bulk-download
Content-Type: application/json

{
  "certificate_ids": [123],
  "format": "pem",
  "include_chain": true,
  "include_private_key": false
}
```

**Breaking Changes:**
- Requires Bearer token with `cert.read` scope
- Bulk download support
- Multiple format options
- Enhanced metadata in response

### 4. Certificate Deletion

#### Before (Legacy)
```bash
DELETE /api/certificates/{id}
```

#### After (Modern)
```bash
POST /api/certificates/batch
Content-Type: application/json

{
  "certificate_ids": [123],
  "operation": "delete",
  "parameters": {
    "reason": "No longer needed"
  }
}
```

**Breaking Changes:**
- Requires Bearer token with `cert.write` scope
- Batch operation format
- Enhanced audit logging
- Reason tracking

### 5. CA Download

#### Before (Legacy)
```bash
GET /api/certificates/ca/download
```

#### After (Modern)
```bash
GET /api/cas/{ca_id}/certificate
Authorization: Bearer vlt_abc123_token-value
```

**Breaking Changes:**
- Requires Bearer token with `ca.read` scope
- CA-specific endpoints
- Enhanced CA management

## Required Scopes

Ensure your Bearer tokens have the appropriate scopes:

| Operation | Required Scope | Description |
|-----------|----------------|-------------|
| View certificates | `cert.read` | Read certificate data and search |
| Create certificates | `cert.write` | Create and update certificates |
| Revoke certificates | `cert.revoke` | Revoke and restore certificates |
| Download certificates | `cert.read` | Download certificates and chains |
| Manage CAs | `ca.read`, `ca.write` | Certificate Authority operations |
| Key operations | `ca.keyop` | CA key rotation and signing |
| Manage profiles | `profile.read`, `profile.write` | Certificate profiles |
| Manage templates | `cert.write` | Certificate templates |
| API tokens | `token.admin` | Token management |
| Audit access | `audit.read` | Audit logs and reports |

## Code Examples

### Python Migration

#### Before (Session-based)
```python
import requests

class VaulTLSLegacyClient:
    def __init__(self, base_url, email, password):
        self.base_url = base_url
        self.session = requests.Session()
        self.login(email, password)
    
    def login(self, email, password):
        response = self.session.post(f'{self.base_url}/api/auth/login', 
                                   json={'email': email, 'password': password})
        response.raise_for_status()
    
    def get_certificates(self):
        response = self.session.get(f'{self.base_url}/api/certificates')
        return response.json()
```

#### After (Bearer Token)
```python
import requests

class VaulTLSModernClient:
    def __init__(self, base_url, bearer_token):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {bearer_token}',
            'Content-Type': 'application/json'
        }
    
    def search_certificates(self, page=1, per_page=50, filters=None):
        payload = {
            'page': page,
            'per_page': per_page,
            'filters': filters or []
        }
        response = requests.post(f'{self.base_url}/api/certificates/search',
                               json=payload, headers=self.headers)
        return response.json()
```

### JavaScript Migration

#### Before (Session-based)
```javascript
class VaulTLSLegacyClient {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }
    
    async login(email, password) {
        const response = await fetch(`${this.baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email, password}),
            credentials: 'include'
        });
        return response.ok;
    }
    
    async getCertificates() {
        const response = await fetch(`${this.baseUrl}/api/certificates`, {
            credentials: 'include'
        });
        return response.json();
    }
}
```

#### After (Bearer Token)
```javascript
class VaulTLSModernClient {
    constructor(baseUrl, bearerToken) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${bearerToken}`,
            'Content-Type': 'application/json'
        };
    }
    
    async searchCertificates(page = 1, perPage = 50, filters = []) {
        const response = await fetch(`${this.baseUrl}/api/certificates/search`, {
            method: 'POST',
            headers: this.headers,
            body: JSON.stringify({page, per_page: perPage, filters})
        });
        return response.json();
    }
}
```

## Environment Variables

Control migration behavior with environment variables:

```bash
# Disable legacy endpoints entirely
VAULTLS_LEGACY_API_ENABLED=false

# Show deprecation warnings in responses
VAULTLS_SHOW_DEPRECATION_WARNINGS=true

# Strict mode - return errors for deprecated endpoints
VAULTLS_STRICT_DEPRECATION_MODE=false
```

## Testing Your Migration

### 1. Verify Token Creation
```bash
curl -X POST https://vaultls.company.com/api/tokens \
  -H "Authorization: Bearer session-token" \
  -H "Content-Type: application/json" \
  -d '{"description": "Test Token", "scopes": ["cert.read"]}'
```

### 2. Test Modern Endpoints
```bash
curl -X POST https://vaultls.company.com/api/certificates/search \
  -H "Authorization: Bearer vlt_abc123_token" \
  -H "Content-Type: application/json" \
  -d '{"page": 1, "per_page": 10}'
```

### 3. Verify Deprecation Warnings
```bash
curl -v https://vaultls.company.com/api/certificates
# Look for X-VaulTLS-Deprecation-Warning header
```

## Support and Resources

- **Migration Examples**: [GitHub Examples](https://github.com/7ritn/VaulTLS/tree/main/examples/api-migration)
- **API Documentation**: [Redoc Documentation](/docs)
- **Support Forum**: [GitHub Discussions](https://github.com/7ritn/VaulTLS/discussions)
- **Issue Tracker**: [GitHub Issues](https://github.com/7ritn/VaulTLS/issues)

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify Bearer token format: `vlt_xxxxxx_token-value`
   - Check token scopes match required permissions
   - Ensure token hasn't expired

2. **Endpoint Not Found**
   - Verify you're using modern endpoint paths
   - Check API documentation for correct endpoints
   - Ensure legacy endpoints aren't disabled

3. **Permission Denied**
   - Verify token has required scopes
   - Check tenant isolation settings
   - Review audit logs for detailed error information

4. **Response Format Changes**
   - Update response parsing for new formats
   - Handle pagination in search responses
   - Check for additional metadata fields

For additional help, please refer to the [API Troubleshooting Guide](troubleshooting.md).
