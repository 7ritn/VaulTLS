# VaulTLS API Endpoints Reference

This document provides detailed information about all available VaulTLS API endpoints.

## Base URL
```
https://your-vaultls-instance.com/api
```

## Authentication
All endpoints (except setup and version) require authentication. See [Authentication Guide](authentication.md) for details.

## Endpoints Overview

### Server Information
- `GET /server/version` - Get server version
- `GET /server/setup` - Check setup status  
- `POST /server/setup` - Initial server setup

### Authentication
- `POST /auth/login` - Login with email/password
- `POST /auth/logout` - Logout current session
- `GET /auth/oidc/login` - Initiate OIDC login
- `GET /auth/oidc/callback` - OIDC callback handler

### Certificates
- `GET /certificates` - List certificates
- `POST /certificates` - Create new certificate
- `GET /certificates/{id}` - Get certificate details
- `GET /certificates/{id}/download` - Download certificate
- `DELETE /certificates/{id}` - Delete certificate
- `GET /certificates/{id}/password` - Get certificate password

### Certificate Authority
- `GET /certificates/ca/download` - Download CA certificate

### Users (Admin only)
- `GET /users` - List all users
- `POST /users` - Create new user
- `GET /users/current` - Get current user info
- `PUT /users/{id}` - Update user
- `DELETE /users/{id}` - Delete user

### Settings (Admin only)
- `GET /settings` - Get application settings
- `PUT /settings` - Update application settings

## Detailed Endpoint Documentation

### Server Information

#### Get Server Version
```http
GET /server/version
```

**Response:**
```json
"1.0.0"
```

#### Check Setup Status
```http
GET /server/setup
```

**Response:**
```json
{
  "setup": true,
  "password": true,
  "oidc": "configured"
}
```

#### Initial Server Setup
```http
POST /server/setup
```

**Request Body:**
```json
{
  "name": "Admin User",
  "email": "admin@example.com", 
  "password": "secure-password"
}
```

**Response:** `204 No Content`

### Authentication

#### Login
```http
POST /auth/login
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password"
}
```

**Response:** `204 No Content`
Sets `auth_token` cookie for session authentication.

#### Logout
```http
POST /auth/logout
```

**Response:** `204 No Content`
Clears authentication cookie.

### Certificates

#### List Certificates
```http
GET /certificates
```

**Authentication:** Required (User role)

**Response:**
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

#### Create Certificate
```http
POST /certificates
```

**Authentication:** Required (Admin role)

**Request Body:**
```json
{
  "name": "api.example.com",
  "certificate_type": "server",
  "dns_names": ["api.example.com", "www.api.example.com"],
  "ip_addresses": ["192.168.1.100"],
  "email_addresses": [],
  "validity_days": 365,
  "key_algorithm": "ecdsa-p256"
}
```

**Response:**
```json
{
  "id": 2,
  "name": "api.example.com", 
  "created_on": 1640995200,
  "valid_until": 1672531200,
  "certificate_type": "server",
  "user_id": 1,
  "renew_method": "manual"
}
```

#### Download Certificate
```http
GET /certificates/{id}/download
```

**Authentication:** Required (User role, own certificates only)

**Query Parameters:**
- `format` (optional): `pkcs12` (default), `pem`, `der`

**Response:** Binary certificate data
- Content-Type: `application/x-pkcs12` for PKCS#12
- Content-Type: `application/x-pem-file` for PEM
- Content-Type: `application/x-x509-ca-cert` for DER

#### Get Certificate Password
```http
GET /certificates/{id}/password
```

**Authentication:** Required (User role, own certificates only)

**Response:**
```json
{
  "password": "generated-pkcs12-password"
}
```

#### Delete Certificate
```http
DELETE /certificates/{id}
```

**Authentication:** Required (Admin role)

**Response:** `204 No Content`

### Certificate Authority

#### Download CA Certificate
```http
GET /certificates/ca/download
```

**Authentication:** Not required

**Query Parameters:**
- `format` (optional): `pem` (default), `der`, `cer`

**Response:** Binary CA certificate data

### Users

#### List Users
```http
GET /users
```

**Authentication:** Required (Admin role)

**Response:**
```json
[
  {
    "id": 1,
    "name": "Admin User",
    "email": "admin@example.com",
    "role": "admin",
    "has_password": true
  }
]
```

#### Create User
```http
POST /users
```

**Authentication:** Required (Admin role)

**Request Body:**
```json
{
  "user_name": "John Doe",
  "user_email": "john@example.com",
  "user_password": "secure-password",
  "role": "user"
}
```

**Response:**
```json
{
  "id": 2,
  "name": "John Doe",
  "email": "john@example.com", 
  "role": "user",
  "has_password": true
}
```

#### Get Current User
```http
GET /users/current
```

**Authentication:** Required (User role)

**Response:**
```json
{
  "id": 1,
  "name": "Admin User",
  "email": "admin@example.com",
  "role": "admin",
  "has_password": true
}
```

#### Update User
```http
PUT /users/{id}
```

**Authentication:** Required (Admin role)

**Request Body:**
```json
{
  "user_name": "Updated Name",
  "user_email": "updated@example.com",
  "user_password": "new-password",
  "role": "admin"
}
```

**Response:** Updated user object

#### Delete User
```http
DELETE /users/{id}
```

**Authentication:** Required (Admin role)

**Response:** `204 No Content`

### Settings

#### Get Settings
```http
GET /settings
```

**Authentication:** Required (Admin role)

**Response:**
```json
{
  "password_enabled": true,
  "password_rule": "medium",
  "oidc": {
    "auth_url": "https://auth.example.com",
    "client_id": "vaultls",
    "configured": true
  },
  "mail": {
    "enabled": true,
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "from_address": "noreply@example.com"
  }
}
```

#### Update Settings
```http
PUT /settings
```

**Authentication:** Required (Admin role)

**Request Body:** Settings object (same structure as GET response)

**Response:** `204 No Content`

## Error Responses

All endpoints return standardized error responses following RFC 7807:

### 400 Bad Request
```json
{
  "type": "https://vaultls.example.com/errors/bad-request",
  "title": "Bad Request",
  "status": 400,
  "detail": "Invalid certificate type specified",
  "instance": "/api/certificates"
}
```

### 401 Unauthorized
```json
{
  "type": "https://vaultls.example.com/errors/unauthorized", 
  "title": "Authentication Required",
  "status": 401,
  "detail": "Valid authentication credentials required",
  "instance": "/api/certificates"
}
```

### 403 Forbidden
```json
{
  "type": "https://vaultls.example.com/errors/forbidden",
  "title": "Insufficient Permissions", 
  "status": 403,
  "detail": "Admin role required for this operation",
  "instance": "/api/users"
}
```

### 404 Not Found
```json
{
  "type": "https://vaultls.example.com/errors/not-found",
  "title": "Resource Not Found",
  "status": 404, 
  "detail": "Certificate with ID 123 not found",
  "instance": "/api/certificates/123"
}
```

### 500 Internal Server Error
```json
{
  "type": "https://vaultls.example.com/errors/internal-error",
  "title": "Internal Server Error",
  "status": 500,
  "detail": "An unexpected error occurred",
  "instance": "/api/certificates"
}
```

## Rate Limiting

API endpoints are subject to rate limiting:

- **Default limit:** 100 requests per minute per IP
- **Authenticated users:** 1000 requests per minute
- **Bearer tokens:** Configurable per token

Rate limit headers are included in responses:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995260
```

When rate limited:
```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60

{
  "type": "https://vaultls.example.com/errors/rate-limit",
  "title": "Rate Limit Exceeded",
  "status": 429,
  "detail": "Rate limit of 1000 requests per minute exceeded",
  "instance": "/api/certificates"
}
```

## Pagination

List endpoints support pagination:

**Query Parameters:**
- `page` - Page number (1-based, default: 1)
- `limit` - Items per page (default: 50, max: 100)

**Response Headers:**
```http
X-Total-Count: 150
X-Page-Count: 3
Link: <https://api.example.com/certificates?page=2>; rel="next",
      <https://api.example.com/certificates?page=3>; rel="last"
```

## Content Types

### Request Content Types
- `application/json` - For JSON request bodies
- `multipart/form-data` - For file uploads (future)

### Response Content Types  
- `application/json` - For JSON responses
- `application/x-pkcs12` - For PKCS#12 certificates
- `application/x-pem-file` - For PEM certificates
- `application/x-x509-ca-cert` - For DER certificates
- `text/plain` - For version endpoint

## CORS Support

The API supports Cross-Origin Resource Sharing (CORS) for web applications:

- **Allowed Origins:** Configurable (default: same origin)
- **Allowed Methods:** GET, POST, PUT, DELETE, OPTIONS
- **Allowed Headers:** Authorization, Content-Type, X-Requested-With
- **Credentials:** Supported for cookie-based authentication

---

For interactive API exploration, visit `/api` on your VaulTLS instance to access the RapiDoc interface.
