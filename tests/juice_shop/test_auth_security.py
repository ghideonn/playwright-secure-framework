"""
Authentication security tests for Juice Shop (UI-driven).

These tests exercise the login flow through the browser using the
LoginPage page object. They verify authentication behavior and check
that a session established via the UI carries secure cookie flags.

Site-specific: tied to Juice Shop's login flow and markup.
"""

import pytest
from playwright.sync_api import Page, BrowserContext

from pages.juice_shop.login_page import LoginPage
from audits.cookies_auditor import CookiesAuditor


@pytest.mark.security
def test_login_page_loads(page: Page, target_config: dict):
    """Sanity check: the login page opens and the form is present."""
    login_page = LoginPage(page, target_config)
    login_page.open()

    # The email input should be visible once the page is ready
    assert page.is_visible(login_page.email_input), "Login email field not found"
    assert page.is_visible(login_page.password_input), "Login password field not found"


@pytest.mark.security
def test_sql_injection_login(page: Page, target_config: dict):
    """Attempt to bypass authentication using a configured SQLi payload.

    Pulls the payload and placeholder password from config, submits them
    through the login form, and checks whether authentication was bypassed
    (indicated by the app storing an auth token).
    """
    login_page = LoginPage(page, target_config)
    login_page.open()

    # Pull attack data from config
    payload = target_config["payloads"]["sql_injection"][0]
    placeholder_pw = target_config["payloads"]["placeholder_password"]

    login_page.login_with_payload(payload, placeholder_pw)

    # Give the app a moment to process and store any auth token
    page.wait_for_timeout(2000)

    # Juice Shop stores an auth token in localStorage on successful login.
    # If the SQLi bypassed auth, a token will be present.
    token = page.evaluate("() => window.localStorage.getItem('token')")

    print(f"\n[SQLi] Payload: {payload}")
    print(f"[SQLi] Auth token after injection: {'PRESENT' if token else 'absent'}")

    # We assert the injection succeeded (token present) to confirm the
    # vulnerability. On a secure site this would fail — which is the point:
    # the test documents whether the target is vulnerable.
    assert token is not None, (
        "SQL injection did not bypass authentication "
        "(no auth token stored). Target may be secure against this payload."
    )


@pytest.mark.security
def test_post_login_cookie_security(
    page: Page,
    context: BrowserContext,
    target_config: dict,
):
    """Check cookie security flags on a session established via the UI.

    Logs in through SQLi to establish a session, then audits the cookies
    the app set — verifying Secure, HttpOnly, and SameSite flags.
    """
    login_page = LoginPage(page, target_config)
    login_page.open()

    # Establish a session via configured payload
    payload = target_config["payloads"]["sql_injection"][0]
    placeholder_pw = target_config["payloads"]["placeholder_password"]
    login_page.login_with_payload(payload, placeholder_pw)
    page.wait_for_timeout(2000)

    # Collect cookies set after login
    cookies = context.cookies()

    # Reuse the cookies auditor to check flags
    auditor = CookiesAuditor()
    result = auditor.audit(
        cookies=cookies,
        config=target_config["cookie_policy"],
        target=target_config["base_url"],
    )

    print(f"\n--- {result.summary()} ---")
    for finding in result.findings:
        status = "PASS" if finding.passed else "FAIL"
        print(f"[{status}] {finding.check}: {finding.detail}")

    if not result.passed:
        failure_lines = [
            f"  [{f.severity.value.upper()}] {f.check}: {f.detail}\n"
            f"      Fix: {f.remediation}"
            for f in result.failures
        ]
        pytest.fail(
            f"Post-login cookie audit failed for {target_config['base_url']}:\n"
            + "\n".join(failure_lines),
            pytrace=False,
        )