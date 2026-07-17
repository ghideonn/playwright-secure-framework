"""
Standalone security audit runner.

Runs all response-driven auditors against a target and generates reports
in multiple formats. Separate from the pytest suite (which gates CI on
pass/fail) — this produces human- and machine-readable audit reports.

Usage:
    python run_audit.py --target juice_shop
"""

import argparse
from pathlib import Path

import yaml
from playwright.sync_api import sync_playwright

from audits.headers_auditor import HeadersAuditor
from audits.cookies_auditor import CookiesAuditor
from audits.cors_auditor import CorsAuditor
from audits.disclosure_auditor import DisclosureAuditor
from reports.console_reporter import ConsoleReporter
from reports.json_reporter import JsonReporter
from reports.markdown_reporter import MarkdownReporter

PROJECT_ROOT = Path(__file__).parent
SITES_CONFIG_DIR = PROJECT_ROOT / "config" / "sites"
REPORTS_OUTPUT_DIR = PROJECT_ROOT / "test-results" / "reports"


def load_config(target: str) -> dict:
    """Load the site configuration for the given target."""
    config_path = SITES_CONFIG_DIR / f"{target}.yaml"
    if not config_path.exists():
        available = [p.stem for p in SITES_CONFIG_DIR.glob("*.yaml")]
        raise FileNotFoundError(
            f"Config not found: {config_path}. Available: {available}"
        )
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_audits(config: dict) -> list:
    """Run all auditors against the target and return their AuditResults."""
    base_url = config["base_url"]
    results = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Navigate once; reuse the response headers and cookies
        response = page.goto(base_url)

        # Wait for network activity to settle before reading cookies.
        # Some cookies are set by client-side scripts after the initial
        # response, so reading immediately makes results depend on timing.
        page.wait_for_load_state("networkidle")

        headers = response.headers
        cookies = context.cookies()

        # Response-driven auditors
        results.append(
            HeadersAuditor().audit(headers, config["security_headers"], base_url)
        )
        results.append(
            CookiesAuditor().audit(cookies, config["cookie_policy"], base_url)
        )
        results.append(
            CorsAuditor().audit(headers, config["cors_policy"], base_url)
        )
        results.append(
            DisclosureAuditor().audit(headers, config["disclosure_policy"], base_url)
        )

        browser.close()

    return results


def write_reports(results: list, target: str) -> None:
    """Print the console report and write JSON + Markdown to files."""
    # Console report to stdout
    print(ConsoleReporter().render(results))

    # File reports
    REPORTS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    json_path = REPORTS_OUTPUT_DIR / f"{target}_audit.json"
    json_path.write_text(JsonReporter().render(results), encoding="utf-8")

    md_path = REPORTS_OUTPUT_DIR / f"{target}_audit.md"
    md_path.write_text(MarkdownReporter().render(results), encoding="utf-8")

    print(f"\nReports written:")
    print(f"  JSON:     {json_path}")
    print(f"  Markdown: {md_path}")


def main():
    parser = argparse.ArgumentParser(description="Run security audits against a target.")
    parser.add_argument(
        "--target",
        default="juice_shop",
        help="Target site config (without .yaml extension). Default: juice_shop",
    )
    args = parser.parse_args()

    config = load_config(args.target)
    results = run_audits(config)
    write_reports(results, args.target)


if __name__ == "__main__":
    main()