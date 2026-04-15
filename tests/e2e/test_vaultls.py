import pytest
from playwright.sync_api import sync_playwright
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import time
import requests
import threading

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

MAILHOG_API_URL = "http://mailhog:8025"

def wait_for_email(subject_keyword, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        res = requests.get(MAILHOG_API_URL + "/api/v2/messages")
        res.raise_for_status()
        messages = res.json().get("items", [])
        for msg in messages:
            subject = msg['Content']['Headers'].get('Subject', [''])[0]
            if subject_keyword in subject:
                return msg
        time.sleep(1)
    raise TimeoutError("Expected email not found")

def delete_all_emails():
    requests.delete(MAILHOG_API_URL + "/api/v1/messages")

def count_table_data_rows(page, table_selector=".active-certs"):
    # Count only tbody tr elements (excludes header rows in thead)
    rows = page.locator(f"{table_selector} tbody tr")
    return rows.count()

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


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

    jws = {
        "protected": protected,
        "payload": encoded_payload,
        "signature": b64url(raw_sig),
    }
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


def run_acme_flow(
    admin_session: requests.Session,
    domain: str,
    challenge_type: str,
    setup_challenge_fn,
    auto_validate: bool = False,
) -> str:
    r = admin_session.post(
        "http://127.0.0.1/api/acme/accounts",
        json={
            "name": f"e2e_{challenge_type}_{domain}",
            "allowed_domains": [domain],
            "auto_validate": auto_validate,
        },
    )
    r.raise_for_status()
    acct = r.json()
    eab_kid = acct["eab_kid"]
    eab_key = b64url_decode(acct["eab_hmac_key"])
    acct_id = acct["id"]

    try:
        client_key = generate_private_key(SECP256R1())
        jwk = ec_key_to_jwk(client_key)
        thumbprint = compute_jwk_thumbprint(jwk)

        # Fetch directory
        directory = requests.get("http://127.0.0.1/api/acme/directory").json()

        # Register ACME account with EAB
        nonce = acme_get_nonce()
        eab_jws = make_eab_jws(eab_kid, eab_key, jwk, directory["newAccount"])
        reg_resp = acme_post(
            client_key,
            directory["newAccount"],
            {
                "termsOfServiceAgreed": True,
                "contact": [],
                "externalAccountBinding": eab_jws,
            },
            nonce,
            jwk=jwk,
        )
        assert reg_resp.status_code == 201, f"new-account failed: {reg_resp.text}"
        kid = reg_resp.headers["Location"]
        nonce = reg_resp.headers["Replay-Nonce"]

        # Create order
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

        # Fetch authorization (POST-as-GET)
        authz_resp = acme_post(
            client_key, order["authorizations"][0], None, nonce, kid=kid
        )
        assert authz_resp.status_code == 200, f"authz failed: {authz_resp.text}"
        authz = authz_resp.json()
        nonce = authz_resp.headers["Replay-Nonce"]

        # Find the requested challenge type
        chall = next(c for c in authz["challenges"] if c["type"] == challenge_type)
        token = chall["token"]
        key_auth = f"{token}.{thumbprint}"

        # Caller sets up the challenge response (HTTP file or DNS TXT record)
        setup_challenge_fn(token, key_auth)

        # Trigger validation
        chall_resp = acme_post(client_key, chall["url"], {}, nonce, kid=kid)
        assert chall_resp.status_code == 200, f"chall trigger failed: {chall_resp.text}"
        nonce = chall_resp.headers["Replay-Nonce"]

        # Poll until order is ready (challenges validated)
        for _ in range(20):
            poll = acme_post(client_key, order_url, None, nonce, kid=kid)
            nonce = poll.headers["Replay-Nonce"]
            status = poll.json().get("status")
            if status in ("ready", "valid", "invalid"):
                break
            time.sleep(1)
        assert poll.json().get("status") == "ready", f"Order not ready: {poll.json()}"

        # Finalize with CSR
        cert_key = generate_private_key(SECP256R1())
        csr_der = make_csr(cert_key, domain)
        fin_resp = acme_post(
            client_key,
            order["finalize"],
            {"csr": b64url(csr_der)},
            nonce,
            kid=kid,
        )
        assert fin_resp.status_code == 200, f"finalize failed: {fin_resp.text}"
        nonce = fin_resp.headers["Replay-Nonce"]

        # Poll until order is valid (certificate issued)
        for _ in range(20):
            poll = acme_post(client_key, order_url, None, nonce, kid=kid)
            nonce = poll.headers["Replay-Nonce"]
            status = poll.json().get("status")
            if status in ("valid", "invalid"):
                break
            time.sleep(1)
        final_order = poll.json()
        assert final_order.get("status") == "valid", f"Order not valid: {final_order}"

        # Download certificate (POST-as-GET)
        cert_resp = acme_post(
            client_key, final_order["certificate"], None, nonce, kid=kid
        )
        assert cert_resp.status_code == 200, f"cert download failed: {cert_resp.text}"
        assert "-----BEGIN CERTIFICATE-----" in cert_resp.text
        return cert_resp.text

    finally:
        admin_session.delete("http://127.0.0.1/api/acme/accounts/{acct_id}")

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
    
@pytest.fixture(scope="session")
def context():
    url = os.getenv("VAULTLS_URL", "http://localhost:5173")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Navigate to setup
        page.goto(url)
        page.wait_for_url("**/first-setup")

        # Fill setup form
        page.fill("#username", "test")
        page.fill("#email", "test@example.com")
        page.fill("#ca_name", "Test CA")
        page.fill("#password", "password")
        page.click("button:has-text('Complete Setup')")

        # Wait for login page
        page.wait_for_url("**/login")

        yield context

        context.close()
        browser.close()

@pytest.fixture
def page(context):
    context.clear_cookies()
    page = context.new_page()
    page.goto("http://127.0.0.1/login")
    page.wait_for_url("**/login")

    # Perform login
    page.fill("#email", "test@example.com")
    page.fill("#password", "password")
    page.click("button:has-text('Login')")
    page.wait_for_url("**/Overview")
    return page

def test_certificates(page):
    delete_all_emails()

    page.goto("http://127.0.0.1/overview")
    page.wait_for_url("**/overview")
    assert "Certificates" in page.locator("h1").inner_text()
    page.click("button:has-text('Create New Certificate')")
    page.fill("#certName", "test_cert")
    page.select_option("#userId", "1")
    page.fill("#certPassword", "password")
    page.locator("#notify-user").check()
    page.click("button:has-text('Create Certificate')")
    page.click("#PasswordButton-1")
    assert "password" in page.locator("#PasswordInput-1").input_value()
    assert count_table_data_rows(page) == 1

    page.wait_for_timeout(1000)
    wait_for_email("VaulTLS: A new certificate is available")

def test_renewal_remind(page):
    delete_all_emails()

    page.goto("http://127.0.0.1/overview")
    page.wait_for_url("**/overview")
    page.click("button:has-text('Create New Certificate')")
    page.fill("#certName", "test_cert_remind")
    page.select_option("#userId", "1")
    page.fill("#certPassword", "password")
    page.fill("#validity", "0")
    page.select_option("#validity_unit", "0")
    page.select_option("#renewMethod", "1")
    page.click("button:has-text('Create Certificate')")

    page.wait_for_timeout(5000)
    wait_for_email("VaulTLS: A certificate is about to expire")
    assert count_table_data_rows(page) == 2

def test_renewal_renew_notify(page):
    delete_all_emails()

    page.goto("http://127.0.0.1/overview")
    page.wait_for_url("**/overview")
    page.click("button:has-text('Create New Certificate')")
    page.fill("#certName", "test_cert_renew")
    page.select_option("#userId", "1")
    page.fill("#certPassword", "password")
    page.fill("#validity", "0")
    page.select_option("#validity_unit", "0")
    page.select_option("#renewMethod", "3")
    page.click("button:has-text('Create Certificate')")

    page.wait_for_timeout(5000)

    wait_for_email("VaulTLS: A certificate was renewed")
    page.reload()
    page.wait_for_timeout(1000)
    assert count_table_data_rows(page) == 4

def test_users(page):
    page.goto("http://127.0.0.1/users")
    page.wait_for_url("**/users")
    assert "Users" in page.locator("h1").inner_text()
    page.click("button:has-text('Create New User')")
    page.fill("#user_name", "test2")
    page.fill("#user_email", "test2@example.com")
    page.fill("#password", "password")
    page.click("button:has-text('Create User')")
    assert "test2" in page.locator("#UserName-2").inner_text()

def test_oidc(context):
    context.clear_cookies()
    page = context.new_page()

    page.goto("http://127.0.0.1/api/auth/oidc/login")
    page.fill("#username-textfield", "test")
    page.fill("#password-textfield", "password")
    page.click("#sign-in-button")

    page.click("#openid-consent-accept")
    page.wait_for_url("**/overview**")
    assert "Certificates" in page.locator("h1").inner_text()

def test_create_ca_and_certificate_with_ca_verification(page):
    """Test that creates a new CA, then a certificate using that CA, and verifies the correct CA was used"""
    page.goto("http://127.0.0.1/ca")
    page.wait_for_url("**/ca")
    assert "Certificate Authorities" in page.locator("h1").inner_text()

    initial_ca_count = count_table_data_rows(page, "table")
    
    # Create new CA
    page.click("#CreateCAButton")
    page.fill("#caName", "Test CA 2")
    page.fill("#validity", "5")
    page.select_option("#validity_unit", "0")  # Select Years (Year = 0)
    page.click("button:has-text('Create CA')")
    
    # Wait for CA creation and verify it was created
    page.wait_for_timeout(2000)
    assert count_table_data_rows(page, "table") == initial_ca_count + 1
    
    # Get the ID of the newly created CA
    new_ca_id_element = page.locator("tbody tr").last.locator("td[id^='CaId-']")
    new_ca_id = new_ca_id_element.inner_text()
    
    # Navigate to certificates tab and create a certificate using the new CA
    page.goto("http://127.0.0.1/overview")
    page.wait_for_url("**/overview")

    # Get initial certificate count
    initial_cert_count = count_table_data_rows(page)
    
    # Create new certificate using the specific CA
    page.click("button:has-text('Create New Certificate')")
    page.fill("#certName", "test_cert_with_new_ca")
    page.select_option("#userId", "1")
    page.fill("#certPassword", "password")
    
    # Select the newly created CA
    page.select_option("#caId", new_ca_id)
    
    page.click("button:has-text('Create Certificate')")

    page.wait_for_timeout(1000)
    
    # Step 3: Verify the certificate was created and uses the correct CA
    assert count_table_data_rows(page) == initial_cert_count + 1

    new_ca_id_element = page.locator("tbody tr").last.locator("td[id^='CaId-']").inner_text()
    assert new_ca_id_element == new_ca_id

def _count_acme_accounts(page) -> int:
    return page.locator("[id^='AcmeId-']").count()


def test_acme_create_account(page):
    page.goto("http://127.0.0.1/acme")
    page.wait_for_url("**/acme")
    assert "ACME Accounts" in page.locator("h1").first.inner_text()

    initial_count = _count_acme_accounts(page)

    page.click("#CreateAcmeAccountButton")
    page.fill("#acmeName", "e2e_create_test")
    page.fill("#acmeDomainInput", "test.internal")
    page.click("button:has-text('Add')")
    page.check("#acmeAutoValidate")
    page.click("button:has-text('Create Account')")
    page.click("button:has-text('Close')")
    page.wait_for_timeout(500)

    assert _count_acme_accounts(page) == initial_count + 1
    assert page.locator("[id^='AcmeName-']").get_by_text("e2e_create_test").is_visible()


def test_acme_edit_account(page):
    page.goto("http://127.0.0.1/acme")
    page.wait_for_url("**/acme")

    page.click("#CreateAcmeAccountButton")
    page.fill("#acmeName", "e2e_edit_target")
    page.fill("#acmeDomainInput", "test.internal")
    page.click("button:has-text('Add')")
    page.click("button:has-text('Create Account')")
    page.click("button:has-text('Close')")
    page.wait_for_timeout(500)

    row = page.locator("tbody tr").filter(has_text="e2e_edit_target").first
    acct_id = row.locator("td[id^='AcmeId-']").inner_text()

    initial_count = _count_acme_accounts(page)
    page.click(f"#EditButton-{acct_id}")
    page.fill("#editAcmeName", "e2e_edit_target_renamed")
    page.select_option("#editAcmeStatus", "deactivated")
    page.click("button:has-text('Save')")
    page.wait_for_timeout(500)

    assert _count_acme_accounts(page) == initial_count - 1


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

    initial_count = _count_acme_accounts(page)
    row = page.locator("tbody tr").filter(has_text="e2e_delete_target").first
    acct_id = row.locator("td[id^='AcmeId-']").inner_text()

    page.click(f"#DeleteButton-{acct_id}")
    page.click("#ConfirmDeleteButton") 
    page.wait_for_timeout(500)

    assert _count_acme_accounts(page) == initial_count - 1

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
