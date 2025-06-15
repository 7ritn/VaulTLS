![VaulTLS Logo](https://github.com/7ritn/VaulTLS/blob/main/assets/logoText.png)

VaulTLS is a modern solution for managing mTLS (mutual TLS) certificates with ease.
It provides a centralized platform for generating, managing, and distributing client TLS certificates for your home lab.

The main reason why I developed VaulTLS was that I didn't like messing with shell scripts and OpenSSL.
I also did not have an overview about the expiration of individual certificates.

## Features

- 🔒 mTLS client and CA certificate management
- 📱 Modern web interface for certificate management
- 🔐 OpenID Connect authentication support
- 📨 Email notifications for certificate expiration
- 🚀 RESTful API for automation
- 🛠 Docker/Podman container support
- ⚡ Built with Rust (backend) and Vue.js (frontend) for performance and reliability

## Screenshots
![WebUI Overview](https://github.com/7ritn/VaulTLS/blob/main/assets/screenshot_overview.jpg)
![WebUI Users](https://github.com/7ritn/VaulTLS/blob/main/assets/screenshot_user.jpg)

## Installation
Installation is managed through a Container. The app *needs* to be behind a reverse proxy for TLS handling.
`VAULTLS_API_SECRET` is required and should be a 256-bit base64 encoded string (`openssl rand -base64 32`).

```bash
podman run -d \
  --name vaultls \
  -p 5173:80 \
  -v vaultls-data:/app/data \
  -e VAULTLS_API_SECRET="[VAULTLS_API_SECRET]" \
  -e VAULTLS_URL="https://vaultls.example.com/" \
  ghcr.io/7ritn/vaultls:latest
```

### Setting up OIDC
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

## Usage
During the first setup a Certificate Authority is automatically created. If OIDC is configured no password needs to be set.
Users can either log in via password or OIDC. If a user first logs in via OIDC their e-mail is matched with all VaulTLS users and linked.
If no user is found a new one is created.

Users can only see certificates created for them. Only admins can create new certificates.
User certificates can be downloaded through the web interface.

The CA certificate to be integrated with your reverse proxy is available as a file at /app/data/ca.cert 
and as download via the API endpoint /api/certificates/ca/download.

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

## Roadmap
- Add database encryption
- Hash passwords in Frontend
- Allow user details to be updated
- Generate new certificates automatically if the old one expires soon
- Add testing
- Add / improve logging
