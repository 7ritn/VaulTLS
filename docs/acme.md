# ACME Support

VaulTLS can act as an ACME Certificate Authority, allowing ACME clients (Traefik, acme.sh, Caddy, cert-manager, etc.) to automatically obtain TLS certificates signed by your VaulTLS CA.

## Prerequisites

- VaulTLS must be accessible over **HTTPS**. ACME clients reject plain HTTP CA server URLs.
- Your ACME client must trust the TLS certificate presented by VaulTLS. If VaulTLS sits behind a reverse proxy with a self-signed or private CA cert, you will need to configure your ACME client to trust that CA (see the client-specific sections below).

## Enabling ACME

Set the `VAULTLS_ACME_ENABLED` environment variable:

```bash
-e VAULTLS_ACME_ENABLED=true
```

Or enable it in the settings UI after startup.

The ACME directory is available at:
```
https://<your-vaultls-instance>/api/acme/directory
```

## Creating an ACME Account

ACME in VaulTLS uses **External Account Binding (EAB)**, which ties ACME registrations to accounts you manage. Each ACME client needs its own account.

1. Log in to VaulTLS as an admin and go to the **ACME** tab.
2. Click **New Account** and configure:
   - **Name** — a label for this account
   - **CA** — which VaulTLS CA will sign certificates for this account
   - **Allowed Domains** — restrict which domains this account may request certificates for (leave blank to allow all)
   - **Auto Validate** — automatically approve certificate orders without manual review
3. After creation, copy the **EAB Key ID** and **EAB HMAC Key** — these are shown only once.

## Traefik

Traefik uses [lego](https://go-acme.github.io/lego/) as its ACME client. Configure a certificate resolver in your static config:

```yaml
certificatesResolvers:
  vaultls:
    acme:
      email: you@example.com
      storage: /acme.json
      caServer: https://vaultls.example.com/api/acme/directory
      httpChallenge:
        entryPoint: web
      eab:
        kid: <eab-key-id>
        hmacEncoded: <eab-hmac-key>
```

Then reference the resolver on any router:

```yaml
# docker-compose label example
- "traefik.http.routers.myapp.tls.certresolver=vaultls"
```

### Trusting a Self-Signed or Private CA Cert

If VaulTLS is behind a reverse proxy presenting a certificate not trusted by the system, lego will refuse to connect. Supply the CA certificate via an environment variable on the Traefik container:

```yaml
environment:
  - LEGO_CA_CERTIFICATES=/certs/vaultls-ca.crt
volumes:
  - ./vaultls-ca.crt:/certs/vaultls-ca.crt:ro
```

`vaultls-ca.crt` should be the PEM certificate that signed Traefik's TLS cert for the VaulTLS hostname (i.e. the cert your reverse proxy presents for `vaultls.example.com`).

> **Note:** `serversTransport.insecureSkipVerify` in Traefik's static config only affects backend connections — it does **not** affect lego's ACME CA connections. `LEGO_CA_CERTIFICATES` is required.

## acme.sh

### Register an account

```bash
./acme.sh --register-account \
  --server https://vaultls.example.com/api/acme/directory \
  --eab-kid <eab-key-id> \
  --eab-hmac-key <eab-hmac-key>
```

### Issue a certificate

```bash
./acme.sh --issue \
  --domain example.com \
  --server https://vaultls.example.com/api/acme/directory \
  --webroot /var/www/html/
```

If VaulTLS presents a certificate not trusted by your system, add `--insecure` to skip CA verification (for testing only):

```bash
./acme.sh --issue --insecure \
  --domain example.com \
  --server https://vaultls.example.com/api/acme/directory \
  --webroot /var/www/html/
```

## HTTP Challenge

The HTTP challenge requires your ACME client to serve a token at:

```
http://<domain>/.well-known/acme-challenge/<token>
```

VaulTLS (as the CA) will make an outbound HTTP request to validate this token. Ensure:

- Port 80 is reachable from the VaulTLS host for each domain being validated.
- If VaulTLS runs in Docker, use `--add-host` or `extra_hosts` entries for any domains that need custom DNS resolution (e.g. internal hosts not in public DNS).

```bash
# docker run example
--add-host="internal.example.com:10.0.5.110"

# docker-compose example
extra_hosts:
  - "internal.example.com:10.0.5.110"
```
