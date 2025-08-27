# VaulTLS API - Getting Started Guide

This guide will help you get started with the VaulTLS API for certificate automation and management.

## Quick Start

### 1. Verify Your VaulTLS Instance

First, check that your VaulTLS instance is running and accessible:

```bash
curl https://your-vaultls-instance.com/api/server/version
```

Expected response:
```
1.0.0
```

### 2. Check Setup Status

```bash
curl https://your-vaultls-instance.com/api/server/setup
```

Expected response:
```json
{
  "setup": true,
  "password": true,
  "oidc": "configured"
}
```

If `setup` is `false`, you'll need to complete the initial setup first.

### 3. Authenticate

Currently, VaulTLS uses session-based authentication. Bearer token authentication is coming in the next release.

#### Login with Session Authentication

```bash
curl -X POST https://your-vaultls-instance.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "your-password"}' \
  -c cookies.txt
```

This saves the session cookie to `cookies.txt` for subsequent requests.

### 4. Test API Access

List certificates using your session:

```bash
curl -X GET https://your-vaultls-instance.com/api/certificates \
  -b cookies.txt
```

Expected response:
```json
[
  {
    "id": 1,
    "name": "example.com",
    "created_on": 1640995200,
    "valid_until": 1672531200,
    "certificate_type": "server",
    "user_id": 1,
    "renew_method": "manual"
  }
]
```

## Common Use Cases

### Certificate Management Agent

Here's a complete example of building a certificate management agent:

```python
#!/usr/bin/env python3
"""
VaulTLS Certificate Management Agent

This script demonstrates how to build an automated certificate
management service using the VaulTLS API.
"""

import requests
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional

class VaulTLSClient:
    def __init__(self, base_url: str, email: str, password: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.login(email, password)
    
    def login(self, email: str, password: str):
        """Authenticate with VaulTLS"""
        response = self.session.post(
            f'{self.base_url}/api/auth/login',
            json={'email': email, 'password': password}
        )
        response.raise_for_status()
        print("✓ Authenticated successfully")
    
    def get_certificates(self) -> List[Dict]:
        """Get all certificates"""
        response = self.session.get(f'{self.base_url}/api/certificates')
        response.raise_for_status()
        return response.json()
    
    def create_certificate(self, name: str, dns_names: List[str], 
                         cert_type: str = 'server') -> Dict:
        """Create a new certificate"""
        payload = {
            'name': name,
            'certificate_type': cert_type,
            'dns_names': dns_names
        }
        response = self.session.post(
            f'{self.base_url}/api/certificates',
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    def download_certificate(self, cert_id: int, format: str = 'pkcs12') -> bytes:
        """Download certificate in specified format"""
        response = self.session.get(
            f'{self.base_url}/api/certificates/{cert_id}/download',
            params={'format': format}
        )
        response.raise_for_status()
        return response.content
    
    def get_certificate_password(self, cert_id: int) -> str:
        """Get PKCS#12 password for certificate"""
        response = self.session.get(
            f'{self.base_url}/api/certificates/{cert_id}/password'
        )
        response.raise_for_status()
        return response.json()['password']
    
    def download_ca_certificate(self, format: str = 'pem') -> bytes:
        """Download CA certificate"""
        response = self.session.get(
            f'{self.base_url}/api/certificates/ca/download',
            params={'format': format}
        )
        response.raise_for_status()
        return response.content

    def revoke_certificate(self, cert_id: int, reason: str = 'cessation_of_operation') -> Dict:
        """Revoke a certificate"""
        payload = {'reason': reason}
        response = self.session.post(
            f'{self.base_url}/api/certificates/{cert_id}/revoke',
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def download_crl(self, ca_id: int, format: str = 'der') -> bytes:
        """Download Certificate Revocation List"""
        response = self.session.get(
            f'{self.base_url}/api/crl/ca/{ca_id}/download',
            params={'format': format}
        )
        response.raise_for_status()
        return response.content

    def check_certificate_status(self, serial_number: str, ca_id: int = None) -> Dict:
        """Check if a certificate is revoked"""
        payload = {'serial_number': serial_number}
        if ca_id:
            payload['ca_id'] = ca_id

        response = self.session.post(
            f'{self.base_url}/api/certificates/status',
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def get_crl_info(self, ca_id: int) -> Dict:
        """Get CRL information"""
        response = self.session.get(f'{self.base_url}/api/crl/ca/{ca_id}/info')
        response.raise_for_status()
        return response.json()

class CertificateManager:
    def __init__(self, client: VaulTLSClient):
        self.client = client
    
    def check_expiring_certificates(self, days_ahead: int = 30) -> List[Dict]:
        """Find certificates expiring within specified days"""
        certificates = self.client.get_certificates()
        expiring = []
        
        cutoff = datetime.now() + timedelta(days=days_ahead)
        
        for cert in certificates:
            valid_until = datetime.fromtimestamp(cert['valid_until'])
            if valid_until <= cutoff:
                days_left = (valid_until - datetime.now()).days
                cert['days_left'] = days_left
                expiring.append(cert)
        
        return expiring
    
    def renew_certificate(self, cert: Dict) -> Dict:
        """Renew an expiring certificate"""
        # For now, create a new certificate with similar parameters
        # In the future, this could use a dedicated renewal endpoint
        new_name = f"{cert['name']}_renewed_{int(time.time())}"
        
        print(f"Renewing certificate: {cert['name']}")
        new_cert = self.client.create_certificate(
            name=new_name,
            dns_names=[cert['name']],  # Simplified - would need to extract actual SANs
            cert_type=cert['certificate_type']
        )
        
        print(f"✓ Created new certificate: {new_cert['id']}")
        return new_cert
    
    def backup_certificate(self, cert: Dict, backup_dir: str = './backups'):
        """Backup certificate to local directory"""
        import os
        os.makedirs(backup_dir, exist_ok=True)
        
        # Download PKCS#12
        pkcs12_data = self.client.download_certificate(cert['id'], 'pkcs12')
        password = self.client.get_certificate_password(cert['id'])
        
        # Save files
        cert_file = f"{backup_dir}/{cert['name']}_{cert['id']}.p12"
        password_file = f"{backup_dir}/{cert['name']}_{cert['id']}.password"
        
        with open(cert_file, 'wb') as f:
            f.write(pkcs12_data)
        
        with open(password_file, 'w') as f:
            f.write(password)
        
        print(f"✓ Backed up certificate to {cert_file}")

    def check_revoked_certificates(self, ca_id: int = 1):
        """Check for revoked certificates and download CRL"""
        try:
            # Get CRL information
            crl_info = self.client.get_crl_info(ca_id)
            print(f"\n🔒 CRL Information for CA {ca_id}:")
            print(f"  CRL Number: {crl_info['crl_number']}")
            print(f"  Revoked Certificates: {crl_info['revoked_count']}")
            print(f"  Total Certificates: {crl_info['total_certificates']}")

            # Download CRL for nginx/caddy
            crl_data = self.client.download_crl(ca_id, 'pem')
            with open(f'ca_{ca_id}.crl', 'wb') as f:
                f.write(crl_data)
            print(f"✓ Downloaded CRL to ca_{ca_id}.crl")

            return crl_info
        except Exception as e:
            print(f"❌ Error checking CRL: {e}")
            return None

    def verify_certificate_status(self, serial_number: str, ca_id: int = None):
        """Verify if a certificate is still valid"""
        try:
            status = self.client.check_certificate_status(serial_number, ca_id)
            print(f"\n🔍 Certificate Status for {serial_number}:")
            print(f"  Status: {status['status']}")
            if status['status'] == 'revoked':
                revocation_date = datetime.fromtimestamp(status['revocation_date'])
                print(f"  Revoked: {revocation_date}")
                print(f"  Reason: {status.get('revocation_reason', 'Unknown')}")
            return status
        except Exception as e:
            print(f"❌ Error checking certificate status: {e}")
            return None

    def monitor_certificates(self):
        """Monitor and report on certificate status"""
        certificates = self.client.get_certificates()
        
        print(f"\n📊 Certificate Status Report")
        print(f"{'Name':<30} {'Type':<10} {'Expires':<12} {'Status':<10}")
        print("-" * 70)
        
        for cert in certificates:
            valid_until = datetime.fromtimestamp(cert['valid_until'])
            days_left = (valid_until - datetime.now()).days
            
            if days_left < 0:
                status = "EXPIRED"
            elif days_left < 7:
                status = "CRITICAL"
            elif days_left < 30:
                status = "WARNING"
            else:
                status = "OK"
            
            print(f"{cert['name']:<30} {cert['certificate_type']:<10} "
                  f"{days_left:>3} days   {status:<10}")

def main():
    """Main automation script"""
    # Configuration
    VAULTLS_URL = "https://vaultls.example.com"
    EMAIL = "admin@example.com"
    PASSWORD = "your-password"
    
    try:
        # Initialize client
        client = VaulTLSClient(VAULTLS_URL, EMAIL, PASSWORD)
        manager = CertificateManager(client)
        
        # Monitor certificates
        manager.monitor_certificates()

        # Check CRL status
        manager.check_revoked_certificates(ca_id=1)

        # Check for expiring certificates
        expiring = manager.check_expiring_certificates(days_ahead=30)
        
        if expiring:
            print(f"\n⚠️  Found {len(expiring)} certificates expiring in 30 days:")
            for cert in expiring:
                print(f"  - {cert['name']} (expires in {cert['days_left']} days)")
                
                # Backup before renewal
                manager.backup_certificate(cert)
                
                # Renew if expiring soon
                if cert['days_left'] < 7:
                    manager.renew_certificate(cert)
        else:
            print("\n✓ No certificates expiring in the next 30 days")
        
        # Download CA certificate for distribution
        ca_cert = client.download_ca_certificate('pem')
        with open('ca.pem', 'wb') as f:
            f.write(ca_cert)
        print("✓ Downloaded CA certificate to ca.pem")
        
    except requests.exceptions.RequestException as e:
        print(f"❌ API Error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
```

### Usage Examples

Save the script as `vaultls_agent.py` and run:

```bash
# Install dependencies
pip install requests

# Run the agent
python vaultls_agent.py
```

### Bash Script Example

For simpler automation, here's a bash script:

```bash
#!/bin/bash
# VaulTLS Certificate Monitor

VAULTLS_URL="https://vaultls.example.com"
EMAIL="admin@example.com"
PASSWORD="your-password"
COOKIE_FILE="/tmp/vaultls_cookies.txt"

# Login and save session
echo "Logging in to VaulTLS..."
curl -s -X POST "$VAULTLS_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
  -c "$COOKIE_FILE"

if [ $? -eq 0 ]; then
  echo "✓ Login successful"
else
  echo "❌ Login failed"
  exit 1
fi

# Get certificates
echo "Fetching certificates..."
CERTS=$(curl -s -X GET "$VAULTLS_URL/api/certificates" -b "$COOKIE_FILE")

if [ $? -eq 0 ]; then
  echo "✓ Retrieved certificates"
  echo "$CERTS" | jq '.[].name'
else
  echo "❌ Failed to retrieve certificates"
  exit 1
fi

# Download CA certificate
echo "Downloading CA certificate..."
curl -s -X GET "$VAULTLS_URL/api/certificates/ca/download" \
  -o "ca.pem"

if [ $? -eq 0 ]; then
  echo "✓ CA certificate saved to ca.pem"
else
  echo "❌ Failed to download CA certificate"
fi

# Download Certificate Revocation List (CRL)
echo "Downloading CRL..."
curl -s -X GET "$VAULTLS_URL/api/crl/ca/1/download" \
  -o "ca.crl"

if [ $? -eq 0 ]; then
  echo "✓ CRL saved to ca.crl"
else
  echo "❌ Failed to download CRL"
fi

# Check certificate status (example)
echo "Checking certificate status..."
curl -s -X POST "$VAULTLS_URL/api/certificates/status" \
  -H "Content-Type: application/json" \
  -d '{"serial_number": "example123", "ca_id": 1}' | jq .

# Cleanup
rm -f "$COOKIE_FILE"
echo "✓ Cleanup complete"
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Certificate Management
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM
  workflow_dispatch:

jobs:
  check-certificates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Check Certificate Status
        env:
          VAULTLS_URL: ${{ secrets.VAULTLS_URL }}
          VAULTLS_EMAIL: ${{ secrets.VAULTLS_EMAIL }}
          VAULTLS_PASSWORD: ${{ secrets.VAULTLS_PASSWORD }}
        run: |
          # Login to VaulTLS
          curl -X POST "$VAULTLS_URL/api/auth/login" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$VAULTLS_EMAIL\",\"password\":\"$VAULTLS_PASSWORD\"}" \
            -c cookies.txt
          
          # Get certificates and check expiration
          CERTS=$(curl -s -X GET "$VAULTLS_URL/api/certificates" -b cookies.txt)
          
          # Process certificates (add your logic here)
          echo "$CERTS" | jq '.[] | select(.valid_until < (now + 2592000))'
```

## Troubleshooting

### Common Issues

#### 1. "Authentication Required" Error
```bash
# Check if login was successful
curl -v -X POST https://your-vaultls-instance.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "your-password"}'
```

#### 2. "CORS Error" in Browser
- Ensure you're accessing the API from the same origin as the web UI
- Check CORS configuration in VaulTLS settings

#### 3. "RapiDoc Not Loading"
- Visit `https://your-vaultls-instance.com/api` directly
- Check browser console for JavaScript errors
- Verify OpenAPI spec is available at `/api/openapi.json`

#### 4. Certificate Creation Fails
- Ensure you have admin privileges
- Check that DNS names are valid
- Verify certificate type is supported

### Getting Help

1. **Check the logs** - VaulTLS logs contain detailed error information
2. **Verify API responses** - Use `curl -v` to see full HTTP responses
3. **Test with RapiDoc** - Use the interactive documentation at `/api`
4. **Check GitHub issues** - Search for similar problems in the VaulTLS repository

## Nginx Configuration with CRL

Here's how to configure nginx to use VaulTLS certificates and CRL validation:

```nginx
# /etc/nginx/sites-available/vaultls-example
server {
    listen 443 ssl http2;
    server_name api.example.com;

    # Server certificate from VaulTLS
    ssl_certificate /etc/ssl/certs/api.example.com.pem;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;

    # CA certificate for client verification
    ssl_client_certificate /etc/ssl/certs/vaultls-ca.pem;

    # Certificate Revocation List
    ssl_crl /etc/ssl/crl/vaultls-ca.crl;

    # Enable client certificate verification
    ssl_verify_client on;
    ssl_verify_depth 2;

    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    location / {
        # Your application
        proxy_pass http://backend;

        # Pass client certificate info to backend
        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
        proxy_set_header X-SSL-Client-S-DN $ssl_client_s_dn;
    }
}
```

### Automated Certificate and CRL Updates

Create a script to automatically update certificates and CRL:

```bash
#!/bin/bash
# /usr/local/bin/update-vaultls-certs.sh

VAULTLS_URL="https://vaultls.example.com"
CERT_DIR="/etc/ssl/certs"
CRL_DIR="/etc/ssl/crl"
PRIVATE_DIR="/etc/ssl/private"

# Download CA certificate
curl -s "$VAULTLS_URL/api/certificates/ca/download" -o "$CERT_DIR/vaultls-ca.pem"

# Download CRL
curl -s "$VAULTLS_URL/api/crl/ca/1/download?format=pem" -o "$CRL_DIR/vaultls-ca.crl"

# Set proper permissions
chmod 644 "$CERT_DIR/vaultls-ca.pem"
chmod 644 "$CRL_DIR/vaultls-ca.crl"

# Reload nginx to pick up new CRL
nginx -t && systemctl reload nginx

echo "✓ Updated VaulTLS CA certificate and CRL"
```

Add to crontab to run every hour:
```bash
# Update VaulTLS certificates and CRL hourly
0 * * * * /usr/local/bin/update-vaultls-certs.sh
```

## Caddy Configuration with CRL

For Caddy users, you can use the revocation validator plugin:

```caddyfile
api.example.com {
    tls {
        client_auth {
            mode require_and_verify
            trusted_ca_cert_file /etc/ssl/certs/vaultls-ca.pem
        }
    }

    # Use the caddy-revocation-validator plugin
    revocation_validator {
        crl_url https://vaultls.example.com/api/crl/ca/1/download
        cache_duration 1h
    }

    reverse_proxy localhost:8080
}
```

## Next Steps

1. **Explore the API** - Visit `/api-docs` on your VaulTLS instance for interactive documentation
2. **Set up monitoring** - Implement certificate expiration and revocation monitoring
3. **Automate renewals** - Build automated certificate renewal workflows
4. **Configure CRL validation** - Set up nginx/caddy to validate certificates against CRL
5. **Integrate with your infrastructure** - Connect VaulTLS to your deployment pipelines

---

For more detailed information, see:
- [Authentication Guide](authentication.md)
- [API Endpoints Reference](endpoints.md)
- [OpenAPI Specification](openapi.yaml)
