"""
Step definitions for login.feature (BDD via pytest-bdd).

Binds each Gherkin step to Python code that drives the LoginPage page
object and reuses the CookiesAuditor. Attack payloads are pulled from
the site config — the feature file describes intent, these steps supply
the concrete data.
"""

import pytest
from pytest_bdd import scenarios, given, when, then, parsers
from playwright.sync_api import Page, BrowserContext

from pages.juice_shop.login_page import LoginPage
from audits.cookies_auditor import CookiesAuditor

# Bind all scenarios from the feature file
scenarios("login.feature")


# ---- Shared state between steps ---------------------------------------------
# pytest-bdd steps share data via a dict fixture (function-scoped).
@pytest.fixture
def context_data():
    """Holds state passed between Given/When/Then steps within a scenario."""
    return {}


# ---- Given ------------------------------------------------------------------
@given("the login page is open")
def open_login_page(page: Page, target_config: dict, context_data):
    """Open the login page and store the page object for later steps."""
    login_page = LoginPage(page, target_config)
    login_page.open()
    context_data["login_page"] = login_page


@given("a session is established through the login form")
def establish_session(page: Page, target_config: dict, context_data):
    """Log in via a configured payload to establish a session."""
    login_page = LoginPage(page, target_config)
    login_page.open()

    payload = target_config["payloads"]["sql_injection"][0]
    placeholder_pw = target_config["payloads"]["placeholder_password"]
    login_page.login_with_payload(payload, placeholder_pw)
    page.wait_for_timeout(2000)

    context_data["login_page"] = login_page


# ---- When -------------------------------------------------------------------
@when("a SQL injection payload is submitted to the login form")
def submit_sql_injection(page: Page, target_config: dict, context_data):
    """Submit a SQL injection payload pulled from config."""
    login_page = context_data["login_page"]

    payload = target_config["payloads"]["sql_injection"][0]
    placeholder_pw = target_config["payloads"]["placeholder_password"]
    login_page.login_with_payload(payload, placeholder_pw)
    page.wait_for_timeout(2000)


@when("the session cookies are audited")
def audit_session_cookies(context: BrowserContext, target_config: dict, context_data):
    """Collect and audit the cookies set for the current session."""
    cookies = context.cookies()
    auditor = CookiesAuditor()
    result = auditor.audit(
        cookies=cookies,
        config=target_config["cookie_policy"],
        target=target_config["base_url"],
    )
    context_data["audit_result"] = result


# ---- Then -------------------------------------------------------------------
@then("the login form should be visible")
def login_form_visible(page: Page, context_data):
    """Assert the login form fields are present."""
    login_page = context_data["login_page"]
    assert page.is_visible(login_page.email_input), "Email field not visible"
    assert page.is_visible(login_page.password_input), "Password field not visible"


@then("authentication should be bypassed")
def authentication_bypassed(page: Page, context_data):
    """Assert an auth token was stored, indicating the bypass succeeded."""
    token = page.evaluate("() => window.localStorage.getItem('token')")
    assert token is not None, (
        "No auth token stored — authentication was not bypassed "
        "(target may be secure against this payload)."
    )


@then("all cookies should have Secure and HttpOnly flags")
def cookies_have_flags(context_data):
    """Assert the cookie audit found no missing-flag issues.

    On a vulnerable target this fails, surfacing the insecure cookies —
    which is the intended outcome of a security audit.
    """
    result = context_data["audit_result"]

    print(f"\n--- {result.summary()} ---")
    for finding in result.findings:
        status = "PASS" if finding.passed else "FAIL"
        print(f"[{status}] {finding.check}: {finding.detail}")

    if not result.passed:
        failure_lines = [
            f"  [{f.severity.value.upper()}] {f.check}: {f.detail}"
            for f in result.failures
        ]
        pytest.fail(
            "Session cookies are missing required security flags:\n"
            + "\n".join(failure_lines),
            pytrace=False,
        )