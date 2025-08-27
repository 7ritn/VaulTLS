# VaulTLS API Troubleshooting Guide

This guide helps you resolve common issues when using the VaulTLS API.

## Quick Diagnostics

### 1. Check API Availability

```bash
# Test if the API is responding
curl -v https://your-vaultls-instance.com/api/server/version
```

**Expected Response:**
```
HTTP/1.1 200 OK
Content-Type: text/plain

1.0.0
```

**If this fails:**
- Verify VaulTLS is running
- Check the URL is correct
- Ensure port 5173 is accessible
- Check firewall/proxy settings

### 2. Check API Documentation Access

```bash
# Test RapiDoc availability
curl -I https://your-vaultls-instance.com/api-docs

# Test OpenAPI spec
curl https://your-vaultls-instance.com/api/openapi.json
```

### 3. Test Authentication

```bash
# Test login endpoint
curl -v -X POST https://your-vaultls-instance.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "your-password"}'
```

## Common Issues and Solutions

### Authentication Problems

#### Issue: "Authentication Required" (401)
```json
{
  "type": "https://vaultls.example.com/errors/unauthorized",
  "title": "Authentication Required",
  "status": 401,
  "detail": "Valid authentication credentials required"
}
```

**Solutions:**
1. **Check login credentials:**
   ```bash
   curl -v -X POST https://your-vaultls-instance.com/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "admin@example.com", "password": "your-password"}' \
     -c cookies.txt
   ```

2. **Verify cookie is saved and used:**
   ```bash
   # Check cookies.txt file exists and has content
   cat cookies.txt
   
   # Use cookies in subsequent requests
   curl https://your-vaultls-instance.com/api/certificates -b cookies.txt
   ```

3. **Check if password authentication is enabled:**
   ```bash
   curl https://your-vaultls-instance.com/api/server/setup
   ```

#### Issue: "Insufficient Permissions" (403)
```json
{
  "type": "https://vaultls.example.com/errors/forbidden",
  "title": "Insufficient Permissions",
  "status": 403,
  "detail": "Admin role required for this operation"
}
```

**Solutions:**
1. **Check user role:**
   ```bash
   curl https://your-vaultls-instance.com/api/users/current -b cookies.txt
   ```

2. **Use admin account for admin operations**
3. **Regular users can only access their own certificates**

### RapiDoc Issues

#### Issue: RapiDoc Page Not Loading

**Check these URLs:**
- `/api-docs` - Interactive documentation
- `/api/openapi.json` - OpenAPI specification
- `/api/docs` - API information endpoint

**Solutions:**
1. **Clear browser cache and reload**
2. **Check browser console for JavaScript errors**
3. **Verify CORS settings if accessing from different domain**
4. **Try accessing directly:**
   ```bash
   curl https://your-vaultls-instance.com/api-docs
   ```

#### Issue: "Try It Out" Not Working in RapiDoc

**Solutions:**
1. **Login first through the web UI or API**
2. **Check CORS configuration**
3. **Use curl for testing instead:**
   ```bash
   # Login first
   curl -X POST https://your-vaultls-instance.com/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "admin@example.com", "password": "your-password"}' \
     -c cookies.txt
   
   # Then test endpoints
   curl https://your-vaultls-instance.com/api/certificates -b cookies.txt
   ```

### Certificate Operations

#### Issue: Certificate Creation Fails
```json
{
  "type": "https://vaultls.example.com/errors/bad-request",
  "title": "Bad Request",
  "status": 400,
  "detail": "Invalid certificate type specified"
}
```

**Solutions:**
1. **Check certificate type is valid:**
   - Use `"server"` or `"client"`

2. **Verify DNS names format:**
   ```json
   {
     "name": "api.example.com",
     "certificate_type": "server",
     "dns_names": ["api.example.com", "www.api.example.com"]
   }
   ```

3. **Ensure you have admin privileges**

#### Issue: Certificate Download Fails

**Solutions:**
1. **Check certificate ID exists:**
   ```bash
   curl https://your-vaultls-instance.com/api/certificates -b cookies.txt
   ```

2. **Verify you own the certificate (non-admin users)**

3. **Check download format is supported:**
   - `pkcs12` (default)
   - `pem`
   - `der`

### Network and Connectivity

#### Issue: CORS Errors in Browser

**Error in browser console:**
```
Access to fetch at 'https://vaultls.example.com/api/certificates' 
from origin 'https://different-domain.com' has been blocked by CORS policy
```

**Solutions:**
1. **Access API from same origin as web UI**
2. **Configure CORS in VaulTLS settings (admin only)**
3. **Use server-side requests instead of browser requests**

#### Issue: SSL/TLS Certificate Errors

**Error:**
```
curl: (60) SSL certificate problem: self-signed certificate
```

**Solutions:**
1. **For testing, use `-k` flag:**
   ```bash
   curl -k https://your-vaultls-instance.com/api/server/version
   ```

2. **For production, use proper SSL certificates**

3. **Add CA certificate to system trust store**

### Rate Limiting

#### Issue: "Too Many Requests" (429)
```json
{
  "type": "https://vaultls.example.com/errors/rate-limit",
  "title": "Rate Limit Exceeded",
  "status": 429,
  "detail": "Rate limit of 100 requests per minute exceeded",
  "retry_after": 60
}
```

**Solutions:**
1. **Wait for the retry period**
2. **Implement exponential backoff in your client**
3. **Reduce request frequency**
4. **Contact admin for higher rate limits**

## Debugging Tips

### Enable Verbose Output

```bash
# Use -v flag for detailed HTTP information
curl -v https://your-vaultls-instance.com/api/certificates -b cookies.txt

# Use -i to include response headers
curl -i https://your-vaultls-instance.com/api/certificates -b cookies.txt
```

### Check Response Headers

```bash
# Look for useful headers
curl -I https://your-vaultls-instance.com/api/certificates -b cookies.txt
```

Important headers:
- `X-RateLimit-*` - Rate limiting information
- `Set-Cookie` - Authentication cookies
- `Content-Type` - Response format
- `Location` - Redirect information

### Validate JSON Payloads

```bash
# Use jq to validate and format JSON
echo '{"email": "admin@example.com", "password": "test"}' | jq .

# Pipe API responses through jq for better formatting
curl https://your-vaultls-instance.com/api/certificates -b cookies.txt | jq .
```

### Test with Different Tools

1. **curl** - Command line testing
2. **Postman** - GUI testing
3. **HTTPie** - User-friendly command line
4. **Browser DevTools** - Network tab inspection

### Example HTTPie Commands

```bash
# Install HTTPie
pip install httpie

# Login
http POST https://your-vaultls-instance.com/api/auth/login \
  email=admin@example.com password=your-password \
  --session=vaultls

# List certificates
http GET https://your-vaultls-instance.com/api/certificates \
  --session=vaultls
```

## Getting Help

### Check Logs

1. **VaulTLS server logs** - Check application logs for detailed error information
2. **Web server logs** - Check reverse proxy logs if using one
3. **Browser console** - Check for JavaScript errors in RapiDoc

### Useful Information to Collect

When reporting issues, include:

1. **VaulTLS version:**
   ```bash
   curl https://your-vaultls-instance.com/api/server/version
   ```

2. **Setup status:**
   ```bash
   curl https://your-vaultls-instance.com/api/server/setup
   ```

3. **Full curl command and response:**
   ```bash
   curl -v https://your-vaultls-instance.com/api/certificates -b cookies.txt
   ```

4. **Browser and version (for RapiDoc issues)**

5. **Operating system and environment details**

### Community Resources

- **GitHub Issues**: [https://github.com/7ritn/VaulTLS/issues](https://github.com/7ritn/VaulTLS/issues)
- **GitHub Discussions**: [https://github.com/7ritn/VaulTLS/discussions](https://github.com/7ritn/VaulTLS/discussions)
- **Documentation**: [https://github.com/7ritn/VaulTLS/tree/main/docs](https://github.com/7ritn/VaulTLS/tree/main/docs)

### Creating a Bug Report

Include this information:

```markdown
## Environment
- VaulTLS Version: [from /api/server/version]
- Operating System: [your OS]
- Browser: [if RapiDoc issue]

## Expected Behavior
[What you expected to happen]

## Actual Behavior
[What actually happened]

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [etc.]

## curl Command and Response
```bash
curl -v [your command]
```

## Additional Context
[Any other relevant information]
```

---

For more help, see:
- [Getting Started Guide](getting-started.md)
- [Authentication Guide](authentication.md)
- [API Endpoints Reference](endpoints.md)
