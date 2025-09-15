![VaulTLS Logo](https://github.com/7ritn/VaulTLS/blob/main/assets/logoText.png)

VaulTLS is a modern solution for managing mTLS (mutual TLS) certificates with ease.
It provides a centralized platform for generating, managing, and distributing client (and server) TLS certificates for your home lab.

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

### Encrypting the Database
By specifying the `VAULTLS_DB_SECRET` environmental variable, the database is encrypted. Data is retained. It is not possible to go back.

### Specifying log level
The default log level is moderate. If a different one is desired, please specify it using the `VAULTLS_LOG_LEVEL` environmental variable.
For bug reports, a trace log report is desirable. Be aware that the trace does contain secrets.

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

The current CA certificate to be integrated with your reverse proxy is available as a file at /app/data/ca/ca.cert 
and as download via the API endpoint /api/certificates/ca/download.

Further API documentation is available at the endpoint /api

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

## Roadmap
- Allow user details to be updated
- Generate new certificates automatically if the old one expires soon
- Improve testing
