# Certificate Templates System

The Certificate Templates system in VaulTLS provides a powerful way to standardize and automate certificate creation through reusable templates with variable substitution and policy enforcement.

## Overview

Certificate templates allow you to:
- **Standardize Certificate Creation** - Define consistent certificate policies and configurations
- **Variable Substitution** - Use placeholders in SAN fields that are replaced during certificate creation
- **Policy Enforcement** - Ensure certificates follow organizational standards
- **Automation Ready** - Perfect for automated certificate provisioning workflows

## Template Structure

### Basic Template Properties

```json
{
  "id": "template-uuid",
  "name": "Server Certificate Template",
  "description": "Standard template for server certificates",
  "certificate_type": "Server",
  "profile_id": "server-profile-id",
  "default_validity_years": 1,
  "default_key_algorithm": "RSA-2048",
  "san_template": "{{hostname}}.{{domain}}",
  "metadata_template": {
    "department": "IT",
    "environment": "{{env}}"
  },
  "tenant_id": "tenant-uuid",
  "created_at": 1640995200
}
```

### Template Variables

Templates support variable substitution using `{{variable_name}}` syntax:

- **SAN Template**: `{{hostname}}.{{domain}}` → `api.example.com`
- **Metadata Template**: `{"env": "{{environment}}"}` → `{"env": "production"}`
- **Multiple Variables**: `{{service}}-{{env}}.{{domain}}` → `api-prod.example.com`

## API Endpoints

### Create Certificate Template

```http
POST /api/templates
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Web Server Template",
  "description": "Template for web server certificates",
  "certificate_type": "Server",
  "profile_id": "web-server-profile",
  "default_validity_years": 1,
  "default_key_algorithm": "RSA-2048",
  "san_template": "{{hostname}}.{{domain}},*.{{hostname}}.{{domain}}",
  "metadata_template": {
    "service_type": "web",
    "environment": "{{env}}"
  }
}
```

### List Templates

```http
GET /api/templates?page=1&per_page=20
Authorization: Bearer <token>
```

### Get Template Details

```http
GET /api/templates/{template_id}
Authorization: Bearer <token>
```

### Update Template

```http
PATCH /api/templates/{template_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "description": "Updated template description",
  "default_validity_years": 2,
  "san_template": "{{hostname}}.{{domain}}"
}
```

### Delete Template

```http
DELETE /api/templates/{template_id}
Authorization: Bearer <token>
```

### Create Certificate from Template

```http
POST /api/templates/{template_id}/certificates
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "API Server Certificate",
  "user_id": 1,
  "template_variables": {
    "hostname": "api",
    "domain": "example.com",
    "env": "production"
  },
  "validity_years": 1
}
```

## Template Examples

### 1. Web Server Template

```json
{
  "name": "Web Server Certificate",
  "description": "Standard template for web servers with wildcard support",
  "certificate_type": "Server",
  "profile_id": "web-server-profile",
  "default_validity_years": 1,
  "default_key_algorithm": "RSA-2048",
  "san_template": "{{hostname}}.{{domain}},*.{{hostname}}.{{domain}}",
  "metadata_template": {
    "service_type": "web",
    "load_balancer": "{{lb_type}}",
    "environment": "{{env}}"
  }
}
```

**Usage:**
```json
{
  "template_variables": {
    "hostname": "www",
    "domain": "company.com",
    "lb_type": "nginx",
    "env": "production"
  }
}
```

**Result:** Certificate with SANs `www.company.com, *.www.company.com`

### 2. Microservice Template

```json
{
  "name": "Microservice Certificate",
  "description": "Template for microservice certificates",
  "certificate_type": "Server",
  "profile_id": "microservice-profile",
  "default_validity_years": 1,
  "default_key_algorithm": "ECDSA-P256",
  "san_template": "{{service}}-{{env}}.{{cluster}}.local,{{service}}.{{namespace}}.svc.cluster.local",
  "metadata_template": {
    "service": "{{service}}",
    "namespace": "{{namespace}}",
    "cluster": "{{cluster}}"
  }
}
```

### 3. Client Certificate Template

```json
{
  "name": "Client Authentication Certificate",
  "description": "Template for client authentication certificates",
  "certificate_type": "Client",
  "profile_id": "client-auth-profile",
  "default_validity_years": 1,
  "default_key_algorithm": "RSA-2048",
  "san_template": null,
  "metadata_template": {
    "user_type": "{{user_type}}",
    "department": "{{department}}"
  }
}
```

## Best Practices

### 1. Template Naming
- Use descriptive names that indicate purpose
- Include certificate type in the name
- Consider environment-specific templates

### 2. Variable Design
- Use consistent variable naming across templates
- Document required vs optional variables
- Provide sensible defaults where possible

### 3. SAN Templates
- Include both specific and wildcard entries when appropriate
- Consider service discovery patterns
- Validate SAN patterns before deployment

### 4. Metadata Templates
- Include operational metadata for certificate tracking
- Use variables for environment-specific values
- Keep metadata consistent across similar certificates

## Security Considerations

### Template Access Control
- Templates inherit tenant isolation
- Require `cert.write` scope for template management
- Template usage requires appropriate certificate creation permissions

### Variable Validation
- Validate template variables before certificate creation
- Sanitize input to prevent injection attacks
- Consider regex validation for critical variables

### Template Auditing
- All template operations are logged in audit trail
- Certificate creation from templates includes template reference
- Track template usage for compliance reporting

## Integration Examples

### Automation Script

```bash
#!/bin/bash
# Create certificate from template with environment variables

TEMPLATE_ID="web-server-template"
HOSTNAME="api"
DOMAIN="example.com"
ENV="production"

curl -X POST "https://vaultls.company.com/api/templates/${TEMPLATE_ID}/certificates" \
  -H "Authorization: Bearer ${VAULTLS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"${HOSTNAME}-${ENV}-certificate\",
    \"user_id\": 1,
    \"template_variables\": {
      \"hostname\": \"${HOSTNAME}\",
      \"domain\": \"${DOMAIN}\",
      \"env\": \"${ENV}\"
    }
  }"
```

### Kubernetes Integration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vaultls-template-config
data:
  template_id: "microservice-template"
  variables: |
    {
      "service": "api-gateway",
      "namespace": "default",
      "cluster": "prod-cluster"
    }
```

## Troubleshooting

### Common Issues

1. **Template Variable Not Found**
   - Ensure all required variables are provided
   - Check variable name spelling and case sensitivity

2. **Invalid SAN Template**
   - Validate SAN template syntax
   - Ensure variables resolve to valid DNS names

3. **Profile Not Found**
   - Verify profile exists and is accessible
   - Check profile permissions for the tenant

4. **Template Creation Fails**
   - Verify `cert.write` scope in Bearer token
   - Check template name uniqueness within tenant
   - Validate all required fields are provided

### Debugging Tips

- Use template test endpoints to validate variable substitution
- Check audit logs for detailed error information
- Verify profile compatibility with certificate type
- Test templates with minimal variable sets first
