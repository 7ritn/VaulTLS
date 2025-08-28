# Webhook Notifications System

VaulTLS provides a comprehensive webhook notification system that sends real-time HTTP notifications for certificate lifecycle events, system alerts, and operational activities.

## Overview

Webhook notifications enable:
- **Real-time Integration** - Immediate notifications for certificate events
- **Automation Triggers** - Trigger external systems based on VaulTLS events
- **Monitoring Integration** - Send alerts to monitoring and alerting systems
- **Compliance Tracking** - Automated compliance and audit workflows

## Supported Events

### Certificate Events
- `CertificateCreated` - New certificate issued
- `CertificateRevoked` - Certificate revoked
- `CertificateExpiring` - Certificate approaching expiration
- `CertificateRenewed` - Certificate renewed
- `CertificateDeleted` - Certificate deleted

### CA Events
- `CaCreated` - New Certificate Authority created
- `CaRotated` - CA key rotated
- `CaRevoked` - CA revoked

### Profile Events
- `ProfileCreated` - New certificate profile created
- `ProfileUpdated` - Certificate profile updated
- `ProfileDeleted` - Certificate profile deleted

### System Events
- `AuditThreshold` - Audit threshold exceeded
- `SystemAlert` - System-level alerts

## Webhook Configuration

### Create Webhook

```http
POST /api/webhooks
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "name": "Certificate Monitoring Webhook",
  "url": "https://monitoring.company.com/webhooks/vaultls",
  "events": [
    "CertificateCreated",
    "CertificateExpiring",
    "CertificateRevoked"
  ],
  "secret": "webhook-hmac-secret-key",
  "headers": {
    "X-Service": "VaulTLS",
    "Authorization": "Bearer monitoring-token"
  },
  "timeout_seconds": 30,
  "retry_attempts": 3
}
```

### Webhook Properties

| Property | Type | Description |
|----------|------|-------------|
| `name` | string | Unique webhook name within tenant |
| `url` | string | HTTPS endpoint URL |
| `events` | array | List of events to subscribe to |
| `secret` | string | Optional HMAC secret for signature verification |
| `headers` | object | Custom HTTP headers |
| `timeout_seconds` | integer | Request timeout (1-300 seconds) |
| `retry_attempts` | integer | Number of retry attempts (0-10) |
| `is_active` | boolean | Enable/disable webhook |

## Webhook Payload Format

### Standard Payload Structure

```json
{
  "event": "CertificateCreated",
  "timestamp": 1640995200,
  "tenant_id": "tenant-uuid",
  "webhook_id": "webhook-uuid",
  "signature": "sha256=abc123...",
  "data": {
    // Event-specific data
  }
}
```

### Certificate Event Data

```json
{
  "event": "CertificateCreated",
  "timestamp": 1640995200,
  "tenant_id": "tenant-uuid",
  "webhook_id": "webhook-uuid",
  "data": {
    "certificate_id": 123,
    "certificate_name": "api.example.com",
    "certificate_type": "Server",
    "serial_number": "1A2B3C4D5E6F",
    "subject": "CN=api.example.com,O=Example Corp",
    "issuer": "CN=Example CA,O=Example Corp",
    "valid_until": 1672531200,
    "status": "active",
    "user_id": 1,
    "ca_id": 1,
    "profile_id": "server-profile",
    "metadata": {
      "environment": "production",
      "service": "api"
    }
  }
}
```

### CA Event Data

```json
{
  "event": "CaCreated",
  "timestamp": 1640995200,
  "tenant_id": "tenant-uuid",
  "webhook_id": "webhook-uuid",
  "data": {
    "ca_id": 1,
    "ca_name": "Production CA",
    "subject": "CN=Production CA,O=Example Corp",
    "valid_until": 1956441600,
    "is_root_ca": true,
    "parent_ca_id": null,
    "key_algorithm": "RSA-4096",
    "created_by_user_id": 1
  }
}
```

### System Alert Data

```json
{
  "event": "SystemAlert",
  "timestamp": 1640995200,
  "tenant_id": "tenant-uuid",
  "webhook_id": "webhook-uuid",
  "data": {
    "alert_type": "certificate_expiry_warning",
    "severity": "warning",
    "message": "5 certificates expiring within 30 days",
    "details": {
      "expiring_count": 5,
      "days_threshold": 30,
      "certificates": [
        {"id": 123, "name": "api.example.com", "expires": 1643587200},
        {"id": 124, "name": "web.example.com", "expires": 1643673600}
      ]
    }
  }
}
```

## Security Features

### HMAC Signature Verification

When a webhook secret is configured, VaulTLS signs the payload using HMAC-SHA256:

```http
X-VaulTLS-Signature: sha256=abc123def456...
```

**Verification Example (Python):**

```python
import hmac
import hashlib

def verify_webhook_signature(payload, signature, secret):
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(
        f"sha256={expected_signature}",
        signature
    )
```

### Custom Headers

Add authentication and identification headers:

```json
{
  "headers": {
    "Authorization": "Bearer your-api-token",
    "X-VaulTLS-Tenant": "production",
    "X-Custom-Header": "custom-value"
  }
}
```

## API Endpoints

### List Webhooks

```http
GET /api/webhooks?page=1&per_page=20
Authorization: Bearer <admin-token>
```

### Get Webhook Details

```http
GET /api/webhooks/{webhook_id}
Authorization: Bearer <admin-token>
```

### Update Webhook

```http
PATCH /api/webhooks/{webhook_id}
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "is_active": false,
  "timeout_seconds": 60,
  "events": ["CertificateExpiring"]
}
```

### Test Webhook

```http
POST /api/webhooks/{webhook_id}/test
Authorization: Bearer <admin-token>
```

### Delete Webhook

```http
DELETE /api/webhooks/{webhook_id}
Authorization: Bearer <admin-token>
```

## Integration Examples

### Slack Notifications

```python
import requests
import json

def handle_vaultls_webhook(payload):
    event = payload['event']
    data = payload['data']
    
    if event == 'CertificateExpiring':
        message = f"⚠️ Certificate '{data['certificate_name']}' expires soon!"
        
        slack_payload = {
            "text": message,
            "attachments": [{
                "color": "warning",
                "fields": [
                    {"title": "Certificate", "value": data['certificate_name'], "short": True},
                    {"title": "Expires", "value": f"<t:{data['valid_until']}:R>", "short": True},
                    {"title": "Serial", "value": data['serial_number'], "short": True}
                ]
            }]
        }
        
        requests.post(SLACK_WEBHOOK_URL, json=slack_payload)
```

### Monitoring System Integration

```python
def handle_certificate_events(payload):
    event = payload['event']
    data = payload['data']
    
    # Send metrics to monitoring system
    if event == 'CertificateCreated':
        send_metric('vaultls.certificates.created', 1, {
            'certificate_type': data['certificate_type'],
            'ca_id': data['ca_id']
        })
    
    elif event == 'CertificateExpiring':
        send_metric('vaultls.certificates.expiring', 1, {
            'certificate_name': data['certificate_name'],
            'days_until_expiry': calculate_days_until_expiry(data['valid_until'])
        })
```

### Automated Certificate Renewal

```python
def handle_expiring_certificate(payload):
    if payload['event'] == 'CertificateExpiring':
        cert_data = payload['data']
        
        # Trigger automated renewal
        renewal_request = {
            "certificate_id": cert_data['certificate_id'],
            "validity_years": 1,
            "reason": "Automated renewal due to expiration"
        }
        
        # Call VaulTLS API to renew certificate
        response = requests.post(
            f"{VAULTLS_URL}/api/certificates/{cert_data['certificate_id']}/renew",
            headers={"Authorization": f"Bearer {VAULTLS_TOKEN}"},
            json=renewal_request
        )
```

## Best Practices

### 1. Webhook Endpoint Design
- Use HTTPS endpoints only
- Implement proper authentication
- Return HTTP 200 for successful processing
- Handle retries gracefully

### 2. Error Handling
- Implement exponential backoff for retries
- Log webhook delivery failures
- Monitor webhook success rates
- Set appropriate timeout values

### 3. Security
- Always verify HMAC signatures when secrets are configured
- Use strong, unique secrets for each webhook
- Implement rate limiting on webhook endpoints
- Validate payload structure before processing

### 4. Performance
- Process webhooks asynchronously
- Avoid long-running operations in webhook handlers
- Use queuing systems for complex processing
- Monitor webhook processing times

## Troubleshooting

### Common Issues

1. **Webhook Not Receiving Events**
   - Check webhook is active (`is_active: true`)
   - Verify event subscription includes desired events
   - Check webhook URL accessibility

2. **Signature Verification Fails**
   - Ensure secret matches webhook configuration
   - Verify HMAC calculation implementation
   - Check payload encoding (UTF-8)

3. **Timeout Errors**
   - Increase `timeout_seconds` value
   - Optimize webhook endpoint performance
   - Check network connectivity

4. **Retry Exhaustion**
   - Check webhook endpoint error responses
   - Verify endpoint returns HTTP 200 for success
   - Review webhook delivery logs

### Debugging

- Use webhook test endpoint to verify configuration
- Check VaulTLS audit logs for webhook delivery attempts
- Monitor webhook endpoint logs for incoming requests
- Verify webhook payload structure matches expected format
