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

## Wildcard Certificates

VaulTLS supports issuing wildcard certificates (e.g. `*.example.com`) via ACME.

**Important:** Wildcard certificates require the **DNS-01 challenge**. The HTTP-01 challenge cannot be used for wildcard identifiers (this is an ACME protocol requirement). Only dns-01 will be offered in the authorization for wildcard orders.

### acme.sh example

```bash
./acme.sh --issue \
  --domain "*.example.com" \
  --server https://vaultls.example.com/api/acme/directory \
  --dns dns_manual
```

Follow the prompts to add the `_acme-challenge.example.com` TXT record, then run the renewal command.

### Traefik example

Use `dnsChallenge` instead of `httpChallenge`:

```yaml
certificatesResolvers:
  vaultls:
    acme:
      email: you@example.com
      storage: /acme.json
      caServer: https://vaultls.example.com/api/acme/directory
      dnsChallenge:
        provider: <your-dns-provider>
      eab:
        kid: <eab-key-id>
        hmacEncoded: <eab-hmac-key>
```

## Allowed Domain Patterns

When creating an ACME account you can restrict which domains it may request certificates for using **Allowed Domains**. Three matching modes are supported:

| Pattern | Matches |
|---------|---------|
| `example.com` | Exactly `example.com` |
| `*.example.com` | One subdomain level: `foo.example.com`, but **not** `a.b.example.com` or `example.com` |
| `**.example.com` | Any depth: `example.com`, `foo.example.com`, `a.b.example.com`, etc. |

Multiple patterns can be entered (one per line or comma-separated) and a domain is permitted if it matches **any** pattern in the list.

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

## DNS Challenge Resolver

By default VaulTLS uses the system resolver to validate DNS-01 challenges. You can override this with the `VAULTLS_ACME_DNS_RESOLVER` environment variable. Three formats are supported:

| Format | Example | Protocol |
|--------|---------|----------|
| `<ip>` or `<ip>:<port>` | `9.9.9.9` or `9.9.9.9:53` | UDP |
| `tls://<host>` | `tls://9.9.9.9` | DNS-over-TLS |
| `https://<url>` | `https://dns.quad9.net/dns-query` | DNS-over-HTTPS |

```bash
-e VAULTLS_ACME_DNS_RESOLVER="9.9.9.9"
```

This is useful when your internal DNS does not expose `_acme-challenge` TXT records publicly, or when you want to use a specific resolver for validation.

## Rate Limiting

ACME order rate limiting is enabled by default and limits each account to **20 orders per 24 hours**. Both the limit and whether it is enforced can be changed in the ACME settings section of the admin UI.

## Email Notifications

If email (SMTP) is configured, VaulTLS can send a notification whenever an ACME certificate is issued. Enable this in the ACME settings section of the admin UI.
