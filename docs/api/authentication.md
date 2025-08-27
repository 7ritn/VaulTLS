# VaulTLS API Authentication Guide

This guide explains how to authenticate with the VaulTLS API for automation and integration purposes.

## Authentication Methods

VaulTLS supports two authentication methods:

### 1. Session-Based Authentication (Web UI)
- Used by the web interface
- Uses HTTP-only cookies with JWT tokens
- Suitable for browser-based applications
- **Not recommended for API automation**

### 2. Bearer Token Authentication (API Automation) 🚀
- **Recommended for API automation and agent services**
- Uses Bearer tokens in the Authorization header
- Supports fine-grained permissions with scopes
- Ideal for ACME-like certificate automation

## Bearer Token Authentication

### Overview
Bearer tokens provide secure, scope-based API access perfect for building automated certificate management services.

### Token Format
```
Authorization: Bearer vlt_abc123_<base64url-encoded-token-value>
```

### Getting Started

#### Step 1: Create an API Token
Currently, API tokens must be created through the database or will be available via the web UI in future versions.

For now, you can create a token using the following approach:

```bash
# Example: Create a token with certificate management permissions
curl -X POST https://your-vaultls-instance.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "your-password"}'

# Then use the session to create certificates
# (Bearer token endpoints will be available in the next release)
```

#### Step 2: Use the Token
```bash
curl -X GET https://your-vaultls-instance.com/api/certificates \
  -H "Authorization: Bearer vlt_abc123_your-token-value-here"
```

### Token Scopes

Bearer tokens support fine-grained permissions through scopes:

#### Certificate Operations
- `cert.read` - View certificates
- `cert.write` - Create and update certificates  
- `cert.revoke` - Revoke certificates
- `cert.download` - Download certificate files

#### CA Operations
- `ca.read` - View CA information
- `ca.write` - Create and update CAs
- `ca.keyop` - Perform CA key operations

#### Profile Operations
- `profile.read` - View certificate profiles
- `profile.write` - Create and update profiles

#### Token Management
- `token.read` - View API tokens
- `token.write` - Create and update tokens
- `token.admin` - Cross-tenant token management

#### Audit and Monitoring
- `audit.read` - View audit logs
- `metrics.read` - View metrics

#### Administrative
- `admin.tenant` - Tenant management

### Example: Building an ACME-like Agent

Here's how to build an automated certificate management service:

```python
import requests
import time
from datetime import datetime, timedelta

class VaulTLSAgent:
    def __init__(self, base_url, token):
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
    
    def get_certificates(self):
        """Get all certificates"""
        response = requests.get(
            f'{self.base_url}/api/certificates',
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def create_certificate(self, name, dns_names, cert_type='client'):
        """Create a new certificate"""
        payload = {
            'name': name,
            'certificate_type': cert_type,
            'dns_names': dns_names
        }
        response = requests.post(
            f'{self.base_url}/api/certificates',
            headers=self.headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    def download_certificate(self, cert_id, format='pkcs12'):
        """Download certificate in specified format"""
        response = requests.get(
            f'{self.base_url}/api/certificates/{cert_id}/download',
            headers=self.headers,
            params={'format': format}
        )
        response.raise_for_status()
        return response.content
    
    def check_expiring_certificates(self, days_ahead=30):
        """Check for certificates expiring soon"""
        certificates = self.get_certificates()
        expiring = []
        
        cutoff = datetime.now() + timedelta(days=days_ahead)
        
        for cert in certificates:
            valid_until = datetime.fromtimestamp(cert['valid_until'])
            if valid_until <= cutoff:
                expiring.append(cert)
        
        return expiring
    
    def renew_certificate(self, cert_id):
        """Renew an existing certificate"""
        # Get current certificate details
        cert = self.get_certificate(cert_id)
        
        # Create new certificate with same parameters
        new_cert = self.create_certificate(
            name=f"{cert['name']}_renewed",
            dns_names=cert.get('dns_names', []),
            cert_type=cert['certificate_type']
        )
        
        return new_cert

# Usage example
agent = VaulTLSAgent('https://vaultls.example.com', 'vlt_abc123_your-token')

# Check for expiring certificates
expiring = agent.check_expiring_certificates(days_ahead=30)
print(f"Found {len(expiring)} certificates expiring in 30 days")

# Renew expiring certificates
for cert in expiring:
    print(f"Renewing certificate: {cert['name']}")
    new_cert = agent.renew_certificate(cert['id'])
    print(f"Created new certificate: {new_cert['id']}")
```

### Error Handling

The API returns standard HTTP status codes with detailed error information:

#### Authentication Errors
```json
{
  "type": "https://vaultls.example.com/errors/unauthorized",
  "title": "Authentication Required",
  "status": 401,
  "detail": "Bearer token is missing or invalid",
  "instance": "/api/certificates"
}
```

#### Authorization Errors
```json
{
  "type": "https://vaultls.example.com/errors/forbidden", 
  "title": "Insufficient Permissions",
  "status": 403,
  "detail": "Token missing required scope: cert.write",
  "instance": "/api/certificates"
}
```

#### Rate Limiting
```json
{
  "type": "https://vaultls.example.com/errors/rate-limit",
  "title": "Rate Limit Exceeded", 
  "status": 429,
  "detail": "Token rate limit of 100 requests per minute exceeded",
  "instance": "/api/certificates",
  "retry_after": 60
}
```

## Session Authentication (Legacy)

For completeness, here's how the current session authentication works:

### Login
```bash
curl -X POST https://your-vaultls-instance.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}' \
  -c cookies.txt
```

### Use Session
```bash
curl -X GET https://your-vaultls-instance.com/api/certificates \
  -b cookies.txt
```

### Logout
```bash
curl -X POST https://your-vaultls-instance.com/api/auth/logout \
  -b cookies.txt
```

## Security Best Practices

1. **Store tokens securely** - Never commit tokens to version control
2. **Use environment variables** - Store tokens in environment variables or secure vaults
3. **Rotate tokens regularly** - Implement token rotation for long-running services
4. **Use minimal scopes** - Only grant the minimum required permissions
5. **Monitor token usage** - Check audit logs for suspicious activity
6. **Implement retry logic** - Handle rate limits and temporary failures gracefully

## Troubleshooting

### Common Issues

#### "Authentication Required" Error
- Verify the token format: `Bearer vlt_xxxxxx_<token-value>`
- Check that the token hasn't expired
- Ensure the token is active and not revoked

#### "Insufficient Permissions" Error  
- Check that your token has the required scopes
- Verify you're accessing the correct tenant's resources

#### "Rate Limit Exceeded" Error
- Implement exponential backoff in your client
- Consider requesting a higher rate limit for your use case

#### RapiDoc Not Loading
- Ensure you're accessing `/api` on your VaulTLS instance
- Check that the OpenAPI specification is available at `/api/openapi.json`
- Verify CORS settings if accessing from a different domain

### Getting Help

- Check the audit logs for detailed error information
- Review the OpenAPI specification at `/api/openapi.json`
- Visit the interactive documentation at `/api` (RapiDoc)

## Next Steps

1. **Set up Bearer tokens** - Contact your VaulTLS administrator to create API tokens
2. **Test with curl** - Verify authentication works with simple curl commands  
3. **Build your agent** - Use the examples above as a starting point
4. **Monitor and iterate** - Use audit logs to optimize your integration

---

*Note: Bearer token management UI and endpoints are coming in the next VaulTLS release. For now, tokens must be created through database operations or by administrators.*
