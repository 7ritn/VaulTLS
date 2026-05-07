import base64
import hashlib
import hmac as hmac_mod
import json
import os
import threading
import time

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
from dnslib import QTYPE, RR, TXT
from dnslib.server import BaseResolver, DNSServer


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


def count_acme_accounts(page) -> int:
    return page.locator("[id^='AcmeId-']").count()


def ec_key_to_jwk(private_key) -> dict:
    pub = private_key.public_key()
    numbers = pub.public_numbers()
    size = 32  # P-256 uses 32-byte coordinates
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(numbers.x.to_bytes(size, "big")),
        "y": b64url(numbers.y.to_bytes(size, "big")),
    }


def compute_jwk_thumbprint(jwk: dict) -> str:
    # RFC 7638: SHA-256 of canonical JSON with required members in lexicographic order
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64url(hashlib.sha256(canonical.encode()).digest())


def admin_login() -> requests.Session:
    session = requests.Session()
    r = session.post(
        "http://127.0.0.1/api/auth/login",
        json={"email": "test@example.com", "password": "password"},
    )
    r.raise_for_status()
    return session


def acme_get_nonce() -> str:
    r = requests.head("http://127.0.0.1/api/acme/new-nonce")
    return r.headers["Replay-Nonce"]


def make_eab_jws(eab_kid: str, eab_key: bytes, jwk: dict, url: str) -> dict:
    """Build the externalAccountBinding JWS (HMAC-SHA256, alg=HS256)."""
    protected = b64url(
        json.dumps(
            {"alg": "HS256", "kid": eab_kid, "url": url}, separators=(",", ":")
        ).encode()
    )
    payload = b64url(json.dumps(jwk, separators=(",", ":")).encode())
    sig_input = f"{protected}.{payload}".encode()
    sig = hmac_mod.new(eab_key, sig_input, hashlib.sha256).digest()
    return {"protected": protected, "payload": payload, "signature": b64url(sig)}


def acme_post(
    private_key,
    url: str,
    payload,
    nonce: str,
    *,
    kid: str = None,
    jwk: dict = None,
) -> requests.Response:
    jws = make_jws(private_key, url, payload, nonce, kid=kid, jwk=jwk)
    return requests.post(
        url, json=jws, headers={"Content-Type": "application/jose+json"}
    )


def make_csr(private_key, domain: str) -> bytes:
    """Return DER-encoded CSR for the given domain."""
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False
        )
        .sign(private_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def make_jws(
    private_key,
    url: str,
    payload,
    nonce: str,
    *,
    kid: str = None,
    jwk: dict = None,
) -> dict:
    header = {"alg": "ES256", "nonce": nonce, "url": url}
    if kid:
        header["kid"] = kid
    else:
        header["jwk"] = jwk

    protected = b64url(json.dumps(header, separators=(",", ":")).encode())
    if payload is None:
        encoded_payload = ""
    else:
        encoded_payload = b64url(json.dumps(payload, separators=(",", ":")).encode())

    sig_input = f"{protected}.{encoded_payload}".encode()
    der_sig = private_key.sign(sig_input, ECDSA(hashes.SHA256()))
    r_int, s_int = decode_dss_signature(der_sig)
    raw_sig = r_int.to_bytes(32, "big") + s_int.to_bytes(32, "big")

    return {"protected": protected, "payload": encoded_payload, "signature": b64url(raw_sig)}


def register_account(
    admin_session: requests.Session,
    name: str,
    allowed_domains: list[str] = None,
    auto_validate: bool = True,
):
    """Create an EAB account and register it; returns (acct_id, kid, private_key)."""
    if allowed_domains is None:
        allowed_domains = ["test.internal"]
    r = admin_session.post(
        "http://127.0.0.1/api/acme/accounts",
        json={"name": name, "allowed_domains": allowed_domains, "auto_validate": auto_validate},
    )
    r.raise_for_status()
    acct = r.json()
    acct_id = acct["id"]
    eab_kid = acct["eab_kid"]
    eab_key = b64url_decode(acct["eab_hmac_key"])

    client_key = generate_private_key(SECP256R1())
    jwk = ec_key_to_jwk(client_key)

    directory = requests.get("http://127.0.0.1/api/acme/directory").json()
    nonce = acme_get_nonce()
    eab_jws = make_eab_jws(eab_kid, eab_key, jwk, directory["newAccount"])
    reg_resp = acme_post(
        client_key,
        directory["newAccount"],
        {"termsOfServiceAgreed": True, "contact": [], "externalAccountBinding": eab_jws},
        nonce,
        jwk=jwk,
    )
    assert reg_resp.status_code == 201, f"account registration failed: {reg_resp.text}"
    kid = reg_resp.headers["Location"]
    return acct_id, kid, client_key


def run_acme_flow(
    admin_session: requests.Session,
    domain: str,
    challenge_type: str,
    setup_challenge_fn,
    auto_validate: bool = False,
) -> str:
    acct_id, kid, client_key = register_account(
        admin_session,
        f"e2e_{challenge_type}_{domain}",
        allowed_domains=[domain],
        auto_validate=auto_validate,
    )

    try:
        jwk = ec_key_to_jwk(client_key)
        thumbprint = compute_jwk_thumbprint(jwk)
        directory = requests.get("http://127.0.0.1/api/acme/directory").json()
        nonce = acme_get_nonce()

        # Submit a new order identifying the domain we want a certificate for.
        # The server responds with authorization URLs that must be satisfied.
        order_resp = acme_post(
            client_key,
            directory["newOrder"],
            {"identifiers": [{"type": "dns", "value": domain}]},
            nonce,
            kid=kid,
        )
        assert order_resp.status_code == 201, f"new-order failed: {order_resp.text}"
        order = order_resp.json()
        order_url = order_resp.headers["Location"]
        nonce = order_resp.headers["Replay-Nonce"]

        # Fetch the authorization object to get the list of available challenges.
        # Each authorization corresponds to one identifier (domain) in the order.
        authz_resp = acme_post(
            client_key, order["authorizations"][0], None, nonce, kid=kid
        )
        assert authz_resp.status_code == 200, f"authz failed: {authz_resp.text}"
        authz = authz_resp.json()
        nonce = authz_resp.headers["Replay-Nonce"]

        # Pick the challenge matching our desired type (http-01 or dns-01) and
        # compute the key authorization: token + "." + JWK thumbprint.
        chall = next(c for c in authz["challenges"] if c["type"] == challenge_type)
        token = chall["token"]
        key_auth = f"{token}.{thumbprint}"

        # Place the key authorization where the server can verify it —
        # either as an HTTP file (http-01) or a DNS TXT record (dns-01).
        setup_challenge_fn(token, key_auth)

        # Notify the server that the challenge is ready to be validated.
        # An empty JSON object `{}` signals readiness per RFC 8555 §7.5.1.
        chall_resp = acme_post(client_key, chall["url"], {}, nonce, kid=kid)
        assert chall_resp.status_code == 200, f"chall trigger failed: {chall_resp.text}"
        nonce = chall_resp.headers["Replay-Nonce"]

        # Poll the order until it transitions to "ready" (all challenges passed)
        # or a terminal state. "ready" means we can now submit the CSR.
        for _ in range(20):
            poll = acme_post(client_key, order_url, None, nonce, kid=kid)
            nonce = poll.headers["Replay-Nonce"]
            status = poll.json().get("status")
            if status in ("ready", "valid", "invalid"):
                break
            time.sleep(1)
        assert poll.json().get("status") == "ready", f"Order not ready: {poll.json()}"

        # Generate a separate key pair for the end-entity certificate and build
        # a CSR for the domain. The CSR key is independent of the ACME account key.
        cert_key = generate_private_key(SECP256R1())
        csr_der = make_csr(cert_key, domain)

        # Finalize the order by submitting the DER-encoded CSR. The server will
        # sign and issue the certificate, transitioning the order to "valid".
        fin_resp = acme_post(
            client_key,
            order["finalize"],
            {"csr": b64url(csr_der)},
            nonce,
            kid=kid,
        )
        assert fin_resp.status_code == 200, f"finalize failed: {fin_resp.text}"
        nonce = fin_resp.headers["Replay-Nonce"]

        # Poll until the order is "valid" (certificate issued) or "invalid".
        for _ in range(20):
            poll = acme_post(client_key, order_url, None, nonce, kid=kid)
            nonce = poll.headers["Replay-Nonce"]
            status = poll.json().get("status")
            if status in ("valid", "invalid"):
                break
            time.sleep(1)
        final_order = poll.json()
        assert final_order.get("status") == "valid", f"Order not valid: {final_order}"

        # Download the issued certificate chain via a POST-as-GET to the
        # certificate URL returned in the finalized order.
        cert_resp = acme_post(
            client_key, final_order["certificate"], None, nonce, kid=kid
        )
        assert cert_resp.status_code == 200, f"cert download failed: {cert_resp.text}"
        assert "-----BEGIN CERTIFICATE-----" in cert_resp.text
        return cert_resp.text

    finally:
        # Always clean up the VaulTLS ACME account regardless of test outcome.
        admin_session.delete(f"http://127.0.0.1/api/acme/accounts/{acct_id}")


class _ChallengeResolver(BaseResolver):
    def __init__(self):
        self._lock = threading.Lock()
        self._records: dict[str, str] = {}

    def set(self, name: str, value: str):
        with self._lock:
            self._records[name.lower().rstrip(".")] = value

    def resolve(self, request, handler):
        reply = request.reply()
        reply.header.aa = 1  # Set Authoritative Answer so resolvers accept the response
        qname = str(request.q.qname).lower().rstrip(".")
        if request.q.qtype == QTYPE.TXT:
            with self._lock:
                val = self._records.get(qname)
            if val:
                reply.add_answer(
                    RR(str(request.q.qname), QTYPE.TXT, rdata=TXT(val))
                )
        return reply


@pytest.fixture(scope="session")
def dns_resolver():
    resolver = _ChallengeResolver()
    server = DNSServer(resolver, port=5353, address="0.0.0.0", tcp=False)
    server.start_thread()
    yield resolver
    server.stop()



def test_acme_create_account(page):
    page.goto("http://127.0.0.1/acme")
    page.wait_for_url("**/acme")
    assert "ACME Accounts" in page.locator("h1").first.inner_text()

    initial_count = count_acme_accounts(page)

    page.click("#CreateAcmeAccountButton")
    page.fill("#acmeName", "e2e_create_test")
    page.fill("#acmeDomainInput", "test.internal")
    page.click("button:has-text('Add')")
    page.check("#acmeAutoValidate")
    page.click("button:has-text('Create Account')")
    page.click("button:has-text('Close')")
    page.wait_for_timeout(500)

    assert count_acme_accounts(page) == initial_count + 1
    assert page.locator("[id^='AcmeName-']").get_by_text("e2e_create_test").is_visible()


def test_acme_edit_account(page):
    page.goto("http://127.0.0.1/acme")
    page.wait_for_url("**/acme")
    assert "ACME Accounts" in page.locator("h1").first.inner_text()
    
    row = page.locator("tbody tr").filter(has_text="e2e_create_test").first
    acct_id = row.locator("td[id^='AcmeId-']").inner_text()

    initial_count = count_acme_accounts(page)
    page.click(f"#EditButton-{acct_id}")
    page.fill("#editAcmeName", "e2e_edit_target_renamed")
    page.select_option("#editAcmeStatus", "deactivated")
    page.click("button:has-text('Save')")
    page.wait_for_timeout(500)

    assert count_acme_accounts(page) == initial_count - 1


def test_acme_deactivate_account(page):
    page.goto("http://127.0.0.1/acme")
    page.wait_for_url("**/acme")

    page.click("#CreateAcmeAccountButton")
    page.fill("#acmeName", "e2e_delete_target")
    page.fill("#acmeDomainInput", "test.internal")
    page.click("button:has-text('Add')")
    page.click("button:has-text('Create Account')")
    page.click("button:has-text('Close')")
    page.wait_for_timeout(500)

    initial_count = count_acme_accounts(page)
    row = page.locator("tbody tr").filter(has_text="e2e_delete_target").first
    acct_id = row.locator("td[id^='AcmeId-']").inner_text()

    page.click(f"#DeleteButton-{acct_id}")
    page.click("#ConfirmDeleteButton")
    page.wait_for_timeout(500)

    assert count_acme_accounts(page) == initial_count - 1


def test_acme_protocol_auto_validate(context):
    """Sanity-check: full ACME flow with auto_validate=True (no real challenge)."""
    session = admin_login()
    pem = run_acme_flow(
        session,
        "test.internal",
        "http-01",
        lambda token, key_auth: None,
        auto_validate=True,
    )
    assert "-----BEGIN CERTIFICATE-----" in pem


def test_acme_http01_challenge(context):
    session = admin_login()
    challenge_dir = "/challenges/.well-known/acme-challenge"
    os.makedirs(challenge_dir, exist_ok=True)

    def setup_http01(token: str, key_auth: str):
        with open(os.path.join(challenge_dir, token), "w") as f:
            f.write(key_auth)

    pem = run_acme_flow(session, "challenge-http", "http-01", setup_http01)
    assert "-----BEGIN CERTIFICATE-----" in pem


def test_acme_dns01_challenge(context, dns_resolver):
    session = admin_login()
    domain = "dns-test.local"

    def setup_dns01(token: str, key_auth: str):
        digest = b64url(hashlib.sha256(key_auth.encode()).digest())
        dns_resolver.set(f"_acme-challenge.{domain}", digest)

    pem = run_acme_flow(session, domain, "dns-01", setup_dns01)
    assert "-----BEGIN CERTIFICATE-----" in pem
