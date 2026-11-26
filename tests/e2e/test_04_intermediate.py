from playwright.sync_api import expect
from conftest import TEST_URL


def ca_id_by_name(page, name):
    cell = page.locator("td[id^='CAName-']", has_text=name)
    expect(cell).to_have_count(1)
    return cell.get_attribute("id").split("-", 1)[1]


def create_ca(page, name, years, parent_id=None):
    page.goto(f"{TEST_URL}/ca")
    page.wait_for_url("**/ca")
    page.click("#CreateCAButton")
    page.fill("#caName", name)
    if parent_id is not None:
        page.click("#caAdvancedToggle")
        page.select_option("#caParent", value=str(parent_id))
    page.fill("#validity", str(years))
    page.select_option("#validity_unit", "0")  # Years (Year = 0)
    expect(page.get_by_role("button", name="Create CA")).to_be_enabled()
    page.click("button:has-text('Create CA')")
    expect(page.locator(f"td[id^='CAName-']", has_text=name)).to_have_count(1)


def issue_cert(page, name, ca_id):
    page.goto(f"{TEST_URL}/overview")
    page.wait_for_url("**/overview")
    page.click("button:has-text('Create New Certificate')")
    page.fill("#certName", name)
    page.select_option("#userId", "1")
    page.fill("#certPassword", "password")
    page.select_option("#caId", str(ca_id))
    page.click("button:has-text('Create Certificate')")
    expect(page.locator(".active-certs tbody tr", has_text=name)).to_have_count(1)


def test_create_intermediate_ca_and_certificate(page):
    create_ca(page, "E2E Root CA", 10)
    root_id = ca_id_by_name(page, "E2E Root CA")

    create_ca(page, "E2E Intermediate CA", 5, parent_id=root_id)
    intermediate_id = ca_id_by_name(page, "E2E Intermediate CA")

    expect(page.locator("th", has_text="Parent CA")).to_be_visible()
    expect(page.locator(f"#CAParent-{intermediate_id}")).to_have_text("E2E Root CA")

    issue_cert(page, "e2e_intermediate_cert", intermediate_id)

    cert_row = page.locator(".active-certs tbody tr", has_text="e2e_intermediate_cert")
    expect(cert_row.locator("td[id^='CaId-']")).to_have_text(str(intermediate_id))


def test_revoke_intermediate_ca(page):
    page.goto("http://127.0.0.1/ca")
    page.wait_for_url("**/ca")
    intermediate_id = ca_id_by_name(page, "E2E Intermediate CA")
    root_id = ca_id_by_name(page, "E2E Root CA")

    expect(page.locator(f"#RevokeCAButton-{root_id}")).to_have_count(0)
    page.click(f"#RevokeCAButton-{intermediate_id}")
    page.click("#ConfirmRevokeCAButton")

    expect(page.locator(f"#CARevoked-{intermediate_id}")).to_be_visible()
    expect(page.locator(f"#RevokeCAButton-{intermediate_id}")).to_have_count(0)

    page.goto("http://127.0.0.1/overview")
    page.wait_for_url("**/overview")
    expect(page.locator(".active-certs tbody tr", has_text="e2e_intermediate_cert")).to_have_count(0)
    page.get_by_text("Revoked Certificates").click()
    cert_row = page.locator(".revoked-certificates-table tbody tr", has_text="e2e_intermediate_cert")
    expect(cert_row.locator("[id^='IssuerRevoked-']")).to_be_visible()
