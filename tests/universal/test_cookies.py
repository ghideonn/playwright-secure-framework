"""
Universal cookie security test.

Runs against any target selected via --target. Navigates to the target,
collects the cookies set in the browser context, audits their security
flags with CookiesAuditor, and asserts the target's cookie policy.
"""

import pytest
from playwright.sync_api import Page, BrowserContext

from audits.cookies_auditor import CookiesAuditor


@pytest.mark.security
def test_cookie_security(
    page: Page,
    context: BrowserContext,
    target_config: dict,
    target_url: str,
):
    """Validate that cookies set by the target carry required security flags.

    Uses pytest-playwright 'page' and 'context' fixtures plus our
    configuration-driven 'target_config' / 'target_url'. Site-agnostic:
    the same test runs against any configured target.
    """
    # Navigate so the target has a chance to set its cookies
    response = page.goto(target_url)
    assert response is not None, f"No response received from {target_url}"

    # Collect cookies from the browser context
    cookies = context.cookies()

    # Run the cookie audit
    auditor = CookiesAuditor()
    result = auditor.audit(
        cookies=cookies,
        config=target_config["cookie_policy"],
        target=target_url,
    )

    # Print a readable audit summary (visible with pytest -s)
    print(f"\n--- {result.summary()} ---")
    for finding in result.findings:
        status = "PASS" if finding.passed else "FAIL"
        print(f"[{status}] {finding.check}: {finding.detail}")

    # Build a detailed failure message listing each insecure cookie flag
    if not result.passed:
        failure_lines = [
            f"  [{f.severity.value.upper()}] {f.check}: {f.detail}\n"
            f"      Fix: {f.remediation}"
            for f in result.failures
        ]
        failure_report = "\n".join(failure_lines)
        pytest.fail(
            f"Cookie security audit failed for {target_url}:\n{failure_report}",
            pytrace=False,
        )