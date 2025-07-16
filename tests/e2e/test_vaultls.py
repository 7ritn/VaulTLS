import pytest
from playwright.sync_api import sync_playwright
import os

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
    page = context.new_page()
    page.goto("http://vaultls/login")
    page.wait_for_url("**/login")

    # Perform login
    page.fill("#email", "test@example.com")
    page.fill("#password", "password")
    page.click("button:has-text('Login')")
    page.wait_for_url("**/Overview")
    return page

def test_dashboard(page):
    page.goto("http://vaultls/overview")
    page.wait_for_url("**/overview")
    assert "Certificates" in page.locator("h1").inner_text()
