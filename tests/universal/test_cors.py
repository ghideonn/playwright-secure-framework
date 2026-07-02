"""
Universal CORS misconfiguration test.

Runs against any target selected via --target. Fetches the target's
response headers via Playwright, audits CORS settings with CorsAuditor,
and asserts there are no permissive misconfigurations.
"""

import pytest
from playwright.sync_api import Page

from audits.cors_auditor import CorsAuditor


@pytest.mark.security
def test_cors_configuration(page: Page, target_config: dict, target_url: str):
    """Validate that the target does not expose permissive CORS settings.

    Site-agnostic: uses the 'page' fixture and configuration-driven
    'target_config' / 'target_url'. Runs against any configured target.
    """
    # Navigate to the target and capture the HTTP response
    response = page.goto(target_url)
    assert response is not None, f"No response received from {target_url}"

    # Run the CORS audit against the response headers
    auditor = CorsAuditor()
    result = auditor.audit(
        headers=response.headers,
        config=target_config["cors_policy"],
        target=target_url,
    )

    # Print a readable audit summary (visible with pytest -s)
    print(f"\n--- {result.summary()} ---")
    for finding in result.findings:
        status = "PASS" if finding.passed else "FAIL"
        print(f"[{status}] {finding.check}: {finding.detail}")

    # Build a detailed failure message listing each CORS misconfiguration
    if not result.passed:
        failure_lines = [
            f"  [{f.severity.value.upper()}] {f.check}: {f.detail}\n"
            f"      Fix: {f.remediation}"
            for f in result.failures
        ]
        failure_report = "\n".join(failure_lines)
        pytest.fail(
            f"CORS audit failed for {target_url}:\n{failure_report}",
            pytrace=False,
        )