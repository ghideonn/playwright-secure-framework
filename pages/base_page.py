"""
Base page object: shared behavior for all page objects (POM foundation).

Every page object inherits from BasePage, which holds the Playwright page,
the site config (for selectors and base_url), and common actions like
navigation and dismissing overlay banners.
"""

from playwright.sync_api import Page


class BasePage:
    """Foundation for all page objects.

    Holds the Playwright page and site config, and provides shared
    navigation and helper actions used across specific page objects.
    """

    def __init__(self, page: Page, config: dict):
        """
        Args:
            page: Playwright Page fixture.
            config: The full site config dict (base_url, selectors, etc.).
        """
        self.page = page
        self.config = config
        self.base_url = config["base_url"]

    def navigate(self, path: str = "/") -> None:
        """Navigate to a path relative to the site's base_url."""
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        self.page.goto(url)

    def dismiss_overlays(self) -> None:
        """Dismiss Juice Shop's welcome banner and cookie message if present.

        These overlays block interaction on first load. We try each and
        ignore failures — they may not always be present.
        """
        nav_selectors = self.config.get("selectors", {}).get("navigation", {})

        for key in ("dismiss_welcome", "dismiss_cookie"):
            selector = nav_selectors.get(key)
            if not selector:
                continue
            try:
                # Short timeout — if the overlay isn't there, move on quickly
                self.page.click(selector, timeout=3000)
            except Exception:
                # Overlay not present or already dismissed — safe to ignore
                pass