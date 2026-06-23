"""
Pytest configuration: shared fixtures, hooks, and CLI options.

This conftest enables configuration-driven testing: the --target flag
selects which site config (config/sites/<target>.yaml) to load, allowing
the same test logic to run against multiple targets.
"""

from pathlib import Path

import pytest
import yaml

# Root directory of the project (where this conftest.py lives)
PROJECT_ROOT = Path(__file__).parent
SITES_CONFIG_DIR = PROJECT_ROOT / "config" / "sites"


# ============================================================
# CLI options
# ============================================================
def pytest_addoption(parser):
    """Register custom command-line options for pytest.

    Usage:
        pytest --target=juice_shop
    """
    parser.addoption(
        "--target",
        action="store",
        default="juice_shop",
        help="Target site config to load from config/sites/ (without .yaml extension)",
    )


# ============================================================
# Configuration fixtures
# ============================================================
@pytest.fixture(scope="session")
def target_name(request) -> str:
    """Return the target site name passed via --target (or the default)."""
    return request.config.getoption("--target")


@pytest.fixture(scope="session")
def target_config(target_name) -> dict:
    """Load and return the site configuration dict for the selected target.

    Reads config/sites/<target_name>.yaml and parses it into a dict.
    Session-scoped: the config is read once per test run, not per test.
    """
    config_path = SITES_CONFIG_DIR / f"{target_name}.yaml"

    if not config_path.exists():
        raise FileNotFoundError(
            f"Site config not found: {config_path}. "
            f"Available configs: {[p.stem for p in SITES_CONFIG_DIR.glob('*.yaml')]}"
        )

    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="session")
def target_url(target_config) -> str:
    """Convenience fixture: return the base_url from the target config.

    Named target_url (not base_url) to avoid collision with the
    base_url fixture provided by the pytest-base-url plugin.
    """
    return target_config["base_url"]


# ============================================================
# Hooks
# ============================================================
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Capture a screenshot when a UI test fails.

    Only acts on the 'call' phase (the actual test body) and only when
    a 'page' fixture is present (i.e. interaction-driven UI tests).
    Response-driven audit tests have no page, so they are skipped.
    """
    outcome = yield
    report = outcome.get_result()

    if report.when == "call" and report.failed:
        page = item.funcargs.get("page")
        if page is not None:
            screenshots_dir = PROJECT_ROOT / "test-results" / "screenshots"
            screenshots_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshots_dir / f"{item.name}.png"
            page.screenshot(path=str(screenshot_path))
            print(f"\n[SCREENSHOT] Failure captured: {screenshot_path}")