# VaulTLS Documentation

This directory contains all documentation for the VaulTLS project.

## Quick Start - API Usage

### 🚀 For API Automation (Recommended)

1. **Access Interactive Documentation**
   ```
   https://your-vaultls-instance.com/api-docs
   ```

2. **Get API Information**
   ```bash
   curl https://your-vaultls-instance.com/api/docs
   ```

3. **Authenticate and Use API**
   ```bash
   # Login (session-based)
   curl -X POST https://your-vaultls-instance.com/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "admin@example.com", "password": "your-password"}' \
     -c cookies.txt

   # List certificates
   curl https://your-vaultls-instance.com/api/certificates -b cookies.txt

   # Download CA certificate (no auth required)
   curl https://your-vaultls-instance.com/api/certificates/ca/download -o ca.pem
   ```

4. **Build Your Agent**
   See [Getting Started Guide](api/getting-started.md) for complete examples.

## Documentation Structure

### API Documentation
- `api/` - API documentation and specifications
- `api/getting-started.md` - **START HERE** - Complete guide with examples
- `api/authentication.md` - Authentication methods and Bearer token guide
- `api/endpoints.md` - Detailed endpoint documentation
- `api/openapi.yaml` - OpenAPI 3.1 specification

### Architecture Documentation
- `architecture/` - System architecture and design documents
- `architecture/database-schema.md` - Database schema documentation
- `architecture/multi-tenancy.md` - Multi-tenancy design
- `architecture/security.md` - Security architecture

### Development Documentation
- `development/` - Developer guides and setup instructions
- `development/setup.md` - Development environment setup
- `development/contributing.md` - Contribution guidelines
- `development/testing.md` - Testing guidelines

### Deployment Documentation
- `deployment/` - Deployment and operations guides
- `deployment/installation.md` - Installation instructions
- `deployment/configuration.md` - Configuration guide
- `deployment/migration.md` - Migration guides

### User Documentation
- `user/` - End-user documentation
- `user/getting-started.md` - Getting started guide
- `user/certificate-management.md` - Certificate management guide
- `user/token-management.md` - API token management guide

## Contributing to Documentation

When adding new documentation:

1. Follow the existing structure
2. Use clear, concise language
3. Include code examples where appropriate
4. Update this README when adding new sections
5. Ensure all links work correctly

## Documentation Standards

- Use Markdown format for all documentation
- Include a table of contents for longer documents
- Use consistent heading styles
- Include examples and screenshots where helpful
- Keep documentation up-to-date with code changes
