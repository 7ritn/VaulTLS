![VaulTLS Logo](https://github.com/7ritn/VaulTLS/blob/main/assets/logoText.png)

VaulTLS is an enterprise-grade solution for managing mTLS (mutual TLS) certificates with advanced automation, comprehensive audit logging, and powerful API capabilities. It provides a centralized platform for generating, managing, and distributing client and server TLS certificates for organizations of all sizes.

Originally developed to eliminate the complexity of shell scripts and OpenSSL management while providing clear visibility into certificate expiration, VaulTLS has evolved into a comprehensive certificate management platform with enterprise features.

## 🚀 Features

### 🔒 **Certificate Management**
- **Multi-CA Support** - Hierarchical certificate authority management with root and intermediate CAs
- **Certificate Profiles** - Policy-driven certificate issuance with EKU, key usage, and SAN validation rules
- **Advanced Search** - Search certificates with 17 fields and 13 operators (eq, ne, like, in, between, etc.)
- **Batch Operations** - Bulk revoke, restore, delete, renew, and download operations
- **Certificate Chain Validation** - Automatic chain building and validation
- **Expiration Monitoring** - Proactive certificate expiration tracking and alerts

### 🔐 **Security & Authentication**
- **Bearer Token Authentication** - HMAC-SHA256 signed API tokens with granular scopes
- **Multi-Tenant Architecture** - Complete tenant isolation for enterprise deployments
- **Scope-Based Authorization** - 13 granular permission scopes (cert.read, cert.write, ca.keyop, etc.)
- **OpenID Connect Support** - Integration with enterprise identity providers
- **RFC 9457 Error Responses** - Standardized Problem Details error format

### 📊 **Audit & Compliance**
- **Comprehensive Audit Logging** - Track all certificate operations with 16+ audit fields
- **Advanced Reporting** - Statistics, analytics, and compliance reports
- **Audit Search & Export** - Complex audit queries with CSV/PDF export capabilities
- **Activity Timeline** - Real-time operational visibility with user correlation
- **Data Retention Controls** - Configurable audit retention for regulatory compliance

### 🛠 **API & Integration**
- **RESTful API** - Complete API coverage for all certificate operations
- **OpenAPI 3.1 Documentation** - Interactive docs with RapiDoc and Redoc
- **Bearer Token Management** - API token lifecycle with rotation and revocation
- **Webhook Support** - Real-time notifications for certificate events
- **Rate Limiting** - Configurable API rate limits for performance protection

### 📱 **User Experience**
- **Modern Web Interface** - Vue.js frontend with responsive design
- **Certificate Statistics** - Comprehensive dashboards and analytics
- **Bulk Download** - ZIP archives with multiple certificate formats
- **Search & Filter** - Advanced filtering with saved searches
- **Email Notifications** - Certificate expiration and event notifications

## Screenshots
![WebUI Overview](https://github.com/7ritn/VaulTLS/blob/main/assets/screenshot_overview.jpg)
![WebUI Users](https://github.com/7ritn/VaulTLS/blob/main/assets/screenshot_user.jpg)

## 🐳 Installation

VaulTLS is deployed as a container and requires a reverse proxy for TLS termination. The `VAULTLS_API_SECRET` is required and should be a cryptographically secure 32+ character string.

### Basic Installation

```bash
podman run -d \
  --name vaultls \
  -p 5173:80 \
  -v vaultls-data:/app/data \
  -e VAULTLS_API_SECRET="your-secure-32-character-secret-key-here" \
  -e VAULTLS_URL="https://vaultls.example.com/" \
  ghcr.io/7ritn/vaultls:latest
```

### Production Installation with Security Controls

```bash
podman run -d \
  --name vaultls \
  -p 5173:80 \
  -v vaultls-data:/app/data \
  -v vaultls-config:/app/config \
  -e VAULTLS_API_SECRET="$(openssl rand -base64 32)" \
  -e VAULTLS_URL="https://vaultls.company.com/" \
  -e VAULTLS_API_DOCS_ENABLED=false \
  -e VAULTLS_API_DOCS_REQUIRE_AUTH=true \
  -e VAULTLS_AUDIT_RETENTION_DAYS=2555 \
  -e VAULTLS_RATE_LIMIT_PER_MINUTE=1000 \
  -e VAULTLS_LOG_LEVEL=info \
  ghcr.io/7ritn/vaultls:latest
```

### 🔐 Security Configuration

#### Database Encryption
Specify `VAULTLS_DB_SECRET` to encrypt the database. **Warning**: This is irreversible.

```bash
-e VAULTLS_DB_SECRET="$(openssl rand -base64 32)"
```

#### API Documentation Security
Control API documentation access for production environments:

```bash
# Disable API documentation entirely
-e VAULTLS_API_DOCS_ENABLED=false

# Require Bearer token authentication for API docs
-e VAULTLS_API_DOCS_REQUIRE_AUTH=true
```

#### Audit and Compliance
Configure audit retention and export limits:

```bash
-e VAULTLS_AUDIT_RETENTION_DAYS=2555        # 7 years retention
-e VAULTLS_AUDIT_EXPORT_MAX_RECORDS=100000  # Export limits
-e VAULTLS_CERTIFICATE_HISTORY_ENABLED=true # Full history tracking
```

### 📝 Logging Configuration
Set log levels for different environments:

```bash
# Development
-e VAULTLS_LOG_LEVEL=debug

# Production
-e VAULTLS_LOG_LEVEL=info

# Troubleshooting (contains secrets - use carefully)
-e VAULTLS_LOG_LEVEL=trace
```

## 🔑 API Authentication

VaulTLS provides comprehensive API access through Bearer token authentication with granular scope-based permissions.

### Creating API Tokens

1. **Web Interface**: Navigate to Settings → API Tokens
2. **API Endpoint**: `POST /api/tokens` with admin authentication

```bash
# Create an API token with certificate management scopes
curl -X POST https://vaultls.company.com/api/tokens \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Certificate Management Token",
    "scopes": ["cert.read", "cert.write", "ca.read"],
    "expires_at": null,
    "rate_limit_per_minute": 1000
  }'
```

### Available Scopes

| Scope | Description |
|-------|-------------|
| `cert.read` | View certificates and search |
| `cert.write` | Create, update, and batch operations |
| `cert.revoke` | Revoke and restore certificates |
| `ca.read` | View certificate authorities |
| `ca.write` | Create and update CAs |
| `ca.keyop` | CA key operations and signing |
| `profile.read` | View certificate profiles |
| `profile.write` | Create and update profiles |
| `token.read` | View API tokens |
| `token.write` | Create and update tokens |
| `token.admin` | Full token management |
| `audit.read` | View audit logs and reports |
| `admin.tenant` | Tenant administration |

### API Documentation

- **Interactive Docs**: `https://your-domain/api-docs` (RapiDoc)
- **Reference Docs**: `https://your-domain/redoc` (Redoc)
- **OpenAPI Spec**: `https://your-domain/api/openapi.json`

### Example API Usage

```bash
# Search certificates
curl -X POST https://vaultls.company.com/api/certificates/search \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "filters": [
      {"field": "status", "operator": "eq", "value": "active"},
      {"field": "valid_until", "operator": "lt", "value": 1735689600}
    ],
    "sort": [{"field": "valid_until", "direction": "asc"}],
    "page": 1,
    "per_page": 50
  }'

# Batch revoke certificates
curl -X POST https://vaultls.company.com/api/certificates/batch \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "certificate_ids": [1, 2, 3],
    "operation": "revoke",
    "parameters": {
      "revocation_reason": 1,
      "revocation_note": "Security incident"
    }
  }'

# Get audit statistics
curl -X GET https://vaultls.company.com/api/audit/statistics?days=30 \
  -H "Authorization: Bearer your-token"
```

## 🔐 Setting up OIDC
To set up OIDC you need to create a new client in your authentication provider. For Authelia a configuration could look like this
```yaml
- client_id: "[client_id]"
  client_name: "vautls"
  client_secret: "[client_secret_hash]"
  public: false
  authorization_policy: "one_factor"
  pkce_challenge_method: "S256"
  redirect_uris:
    - "https://vaultls.example.com/api/auth/oidc/callback"
  scopes:
    - "openid"
    - "profile"
    - "email"
  userinfo_signed_response_alg: "none"
```
For VaulTLS the required variables can be configured via environmental variables or web UI.

| Environment Variable        | Value                                                |
|-----------------------------|------------------------------------------------------|
| `VAULTLS_OIDC_AUTH_URL`     | `https://auth.example.com`                           |
| `VAULTLS_OIDC_CALLBACK_URL` | `https://vaultls.example.com/api/auth/oidc/callback` |
| `VAULTLS_OIDC_ID`           | `[client_id]`                                        |
| `VAULTLS_OIDC_SECRET`       | `[client_secret]`                                    |

If VaulTLS claims that OIDC is not configured, the most likely cause is that it couldn't discover the OIDC provider based on the `VAULTLS_OIDC_AUTH_URL` given. In general the the base url to the auth provider should be enough. For Authentik the required URL path is `/application/o/<application slug>/`. If that doesn't work, directly specify the .well_known url. 

### Container Secrets
Certain environment variables can be Container Secrets instead of regular variables.
VaulTLS will try to read secrets from `/run/secrets/<ENV_NAME>`, if you want to specify a different path, you can do so in the environmental variable.
The following variables support secrets:
- VAULTLS_API_SECRET
- VAULTLS_DB_SECRET
- VAULTLS_OIDC_SECRET

## Usage
During the first setup a Certificate Authority is automatically created. If OIDC is configured no password needs to be set.
Users can either log in via password or OIDC. If a user first logs in via OIDC their e-mail is matched with all VaulTLS users and linked.
If no user is found a new one is created.

Users can only see certificates created for them. Only admins can create new certificates.
User certificates can be downloaded through the web interface.

The CA certificate to be integrated with your reverse proxy is available as a file at /app/data/ca.cert
and as download via the API endpoint /api/certificates/ca/download.

## API Documentation 🚀

VaulTLS provides a comprehensive REST API for automation and integration:

- **📖 Getting Started Guide**: [docs/api/getting-started.md](docs/api/getting-started.md)
- **🔍 Interactive Documentation**: Visit `/api-docs` on your VaulTLS instance
- **🔐 Authentication Guide**: [docs/api/authentication.md](docs/api/authentication.md)
- **📋 API Reference**: [docs/api/endpoints.md](docs/api/endpoints.md)
- **📄 OpenAPI Specification**: [docs/api/openapi.yaml](docs/api/openapi.yaml)

### Quick API Example

```bash
# Login and get session cookie
curl -X POST https://your-vaultls-instance.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "your-password"}' \
  -c cookies.txt

# List certificates
curl https://your-vaultls-instance.com/api/certificates -b cookies.txt

# Download CA certificate (no authentication required)
curl https://your-vaultls-instance.com/api/certificates/ca/download -o ca.pem
```

### Building Certificate Automation

The API is perfect for building ACME-like certificate automation services. See the [Getting Started Guide](docs/api/getting-started.md) for complete Python and Bash examples.

### PKCS12 Passwords
By default, PKCS12 passwords are optional and certificates will be generated with no password. In the settings page, the PKCS12 password requirements can be set with the following options:

| PKCS12 Password Rule  | Result                                              |
|-----------------------|-----------------------------------------------------|
| Optional              | Passwords are optional and can be blank             |
| Required              | Passwords are required, but can be system generated |
| System Generated      | Random passwords will be generated                  |

Passwords are stored in the database and retrieved from the web interface only when the user clicks on view password.

### Server Certificates
Since version v0.7.0 VaulTLS also has support for server certificates.
The user flow remains quite similar with the difference that SAN DNS entries can be specified.
Download is also using a possibly password-protected PKCS#12 file.
Since most reverse proxies require the certificate and private key to be supplied separately, the p12 may need to be split.
This can be done, for example, with openssl:
```sh
openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -nokeys
openssl pkcs12 -in INFILE.p12 -out OUTFILE.key -nodes -nocerts
```

### Caddy
To use caddy as reverse proxy for the VaulTLS app, a configuration like the following is required.
```caddyfile
reverse_proxy 127.0.0.1:5173
```
To integrate the CA cert for client validation, you can either use a file or http based approach. Extend your TLS instruction for that with the client_auth section. Documentation here: [https://caddyserver.com/docs/caddyfile/directives/tls#client_auth](https://caddyserver.com/docs/caddyfile/directives/tls#client_auth).

File based:
```caddyfile
tls {
  client_auth {
    mode <usually verify_if_given OR require_and_verify>
    trust_pool file {
      pem_file <Path to VaulTLS Directory>/ca.cert
    }
  }
}
```

HTTP based:
```caddyfile
tls {
  client_auth {
    mode <usually verify_if_given OR require_and_verify>
    trust_pool http {
      endpoints <Address of VaulTLS Instance such as 127.0.0.1:5173>/api/certificates/ca/download
    }
  }
}
```

If you choose `verify_if_given`, you can still block clients for apps that you want to require client authentication:
```caddyfile
@blocked {
  vars {tls_client_subject} ""
}
abort @blocked
```

## 📊 Enterprise Features

### Certificate Profiles
Define reusable certificate policies with validation rules:

```json
{
  "name": "Server Certificate Profile",
  "eku": ["serverAuth"],
  "key_usage": ["digitalSignature", "keyEncipherment"],
  "san_rules": {
    "dns_names": [
      {"pattern": "*.company.com", "required": false, "max_count": 5}
    ]
  },
  "default_days": 365,
  "max_days": 730,
  "key_alg_options": ["RSA-2048", "RSA-4096", "ECDSA-P256"]
}
```

### Advanced Certificate Search
Search certificates with powerful filtering:

- **17 Searchable Fields**: name, commonName, serialNumber, issuer, subject, status, etc.
- **13 Operators**: eq, ne, lt, gt, like, in, between, contains, startsWith, endsWith
- **Complex Queries**: Multiple filters with AND/OR logic
- **Sorting**: Multi-field sorting with ascending/descending order

### Audit & Compliance
Comprehensive audit logging for regulatory compliance:

- **Complete Audit Trail**: All certificate operations tracked
- **Advanced Reporting**: Statistics, analytics, and compliance reports
- **Data Export**: CSV/PDF export for external analysis
- **Retention Controls**: Configurable data retention policies
- **Activity Timeline**: Real-time operational visibility

### Multi-Tenant Architecture
Enterprise-ready multi-tenant support:

- **Complete Tenant Isolation**: Data, certificates, and audit logs
- **Tenant-Specific Policies**: Custom certificate profiles per tenant
- **Granular Access Control**: Scope-based permissions per tenant
- **Audit Separation**: Tenant-isolated audit trails

## 🛠 Development

To run VaulTLS in development mode, you'll need to set up both the backend (Rust) and frontend (Vue.js) components.

### Prerequisites

- Rust (latest stable version)
- Node.js (v18 or later)
- SQLite

### Backend Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/7ritn/VaulTLS.git
   cd VaulTLS
   ```

2. Set up environment variables:
   ```bash
   export VAULTLS_API_SECRET="dev-secret-key-32-characters-long-123"
   export VAULTLS_DATABASE_URL="./dev.db"
   export VAULTLS_MAIL_HOST="localhost"
   export VAULTLS_MAIL_PORT="1025"
   export VAULTLS_MAIL_FROM="dev@vaultls.local"
   export VAULTLS_API_DOCS_ENABLED="true"
   export VAULTLS_API_DOCS_REQUIRE_AUTH="false"
   export VAULTLS_LOG_LEVEL="debug"
   ```

3. Run the backend:
   ```bash
   cd backend
   cargo run
   ```

### Frontend Setup

1. Install dependencies:
   ```bash
   cd frontend
   npm install
   ```

2. Start the development server:
   ```bash
   npm run dev
   ```

The application will be available at `http://localhost:5173` with the backend API at `http://localhost:8000`.

### Testing

Run the comprehensive test suite:

```bash
# Backend tests
cd backend
cargo test

# Integration tests
cargo test --test integration_tests

# Frontend tests
cd frontend
npm run test
```

## 🗺 Roadmap

### Completed ✅
- ✅ Bearer Token Authentication with granular scopes
- ✅ Multi-CA Support with hierarchical management
- ✅ Certificate Profiles with policy enforcement
- ✅ Advanced Certificate Search (17 fields, 13 operators)
- ✅ Batch Operations (revoke, restore, delete, renew)
- ✅ Comprehensive Audit Logging and Reporting
- ✅ OpenAPI 3.1 Documentation with RapiDoc/Redoc
- ✅ RFC 9457 Problem Details error responses
- ✅ Multi-tenant architecture with complete isolation
- ✅ Certificate chain validation and management

### In Progress 🚧
- 🚧 Frontend UI enhancements for new features
- 🚧 Certificate analytics dashboard
- 🚧 Advanced audit visualization

### Planned 📋
- 📋 Automatic certificate renewal workflows
- 📋 Certificate template system
- 📋 Webhook notifications for certificate events
- 📋 ACME protocol support
- 📋 Hardware Security Module (HSM) integration
- 📋 Certificate transparency logging
- 📋 Advanced user management and RBAC

## ⚙️ Configuration Reference

For complete environment variable configuration options, see [docs/configuration/environment-variables.md](docs/configuration/environment-variables.md).

### Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULTLS_API_SECRET` | *Required* | 32+ character secret for Bearer token signing |
| `VAULTLS_API_DOCS_ENABLED` | `true` | Enable/disable API documentation |
| `VAULTLS_API_DOCS_REQUIRE_AUTH` | `false` | Require Bearer token for API docs |
| `VAULTLS_AUDIT_RETENTION_DAYS` | `2555` | Audit log retention period (7 years) |
| `VAULTLS_RATE_LIMIT_PER_MINUTE` | `1000` | Default API rate limit |
| `VAULTLS_LOG_LEVEL` | `info` | Logging level (trace, debug, info, warn, error) |

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch from `development`
3. Make your changes with tests
4. Submit a pull request to `development`

### Code Quality

- All new features must include comprehensive tests
- Follow Rust and Vue.js best practices
- Maintain API documentation with OpenAPI specs
- Include audit logging for all certificate operations

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Rocket](https://rocket.rs/) (Rust web framework)
- Frontend powered by [Vue.js](https://vuejs.org/)
- Certificate management using [OpenSSL](https://www.openssl.org/)
- API documentation with [RapiDoc](https://rapidocweb.com/) and [Redoc](https://redocly.github.io/redoc/)

---

**VaulTLS** - Enterprise Certificate Management Made Simple 🔒
