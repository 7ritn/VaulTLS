import pytest
from playwright.sync_api import sync_playwright
import os
import time
import requests

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

def count_table_data_rows(page, table_selector="table"):
    # Count only tbody tr elements (excludes header rows in thead)
    rows = page.locator(f"{table_selector} tbody tr")
    return rows.count()


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

    time.sleep(1)
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
    page.select_option("#renewMethod", "1")
    page.click("button:has-text('Create Certificate')")

    time.sleep(5)
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
    page.select_option("#renewMethod", "3")
    page.click("button:has-text('Create Certificate')")

    time.sleep(5)

    wait_for_email("VaulTLS: A certificate was renewed")
    page.reload()
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