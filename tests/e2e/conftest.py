import os

import pytest
from playwright.sync_api import sync_playwright

BASE_URL = os.getenv("BASE_URL", "http://localhost:5173").rstrip("/")
TEST_URL = os.getenv("TEST_URL", BASE_URL).rstrip("/")


@pytest.fixture(scope="session")
def context():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        page.goto(TEST_URL)
        page.wait_for_url("**/first-setup")

        page.fill("#username", "test")
        page.fill("#email", "test@example.com")
        page.fill("#ca_name", "Test CA")
        page.fill("#password", "password")
        page.click("button:has-text('Complete Setup')")

        page.wait_for_url("**/login")

        yield context

        context.close()
        browser.close()


@pytest.fixture
def page(context):
    context.clear_cookies()
    page = context.new_page()
    page.goto(f"{TEST_URL}/login")
    page.wait_for_url("**/login")

    page.fill("#email", "test@example.com")
    page.fill("#password", "password")
    page.click("button:has-text('Login')")
    page.wait_for_url("**/Overview")
    return page
