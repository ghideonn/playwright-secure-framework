"""
Universal security headers test.

Runs against any target selected via --target. Fetches the target's
response headers via Playwright, audits them with HeadersAuditor, and
asserts that all required security headers are present.
"""

import pytest
from playwright.sync_api import Page

from audits.headers_auditor import HeadersAuditor


@pytest.mark.security
def test_security_headers(page: Page, target_config: dict, target_url: str):
    """Validate that the target serves all required security headers.

    Uses the pytest-playwright 'page' fixture and our configuration-driven
    'target_config' / 'target_url' fixtures. Site-agnostic: the same test
    runs against any configured target.
    """
    # Navigate to the target and capture the HTTP response
    response = page.goto(target_url)
    assert response is not None, f"No response received from {target_url}"

    # Run the headers audit against the response
    auditor = HeadersAuditor()
    result = auditor.audit(
        headers=response.headers,
        config=target_config["security_headers"],
        target=target_url,
    )

    # Print a readable audit summary (visible with pytest -s)
    print(f"\n--- {result.summary()} ---")
    for finding in result.findings:
        status = "PASS" if finding.passed else "FAIL"
        print(f"[{status}] {finding.check}: {finding.detail}")

    # Build a detailed failure message listing each vulnerability + remediation
    if not result.passed:
        failure_lines = [
            f"  [{f.severity.value.upper()}] {f.check}: {f.detail}\n"
            f"      Fix: {f.remediation}"
            for f in result.failures
        ]
        failure_report = "\n".join(failure_lines)
        pytest.fail(
            f"Security headers audit failed for {target_url}:\n{failure_report}",
            pytrace=False,
        )