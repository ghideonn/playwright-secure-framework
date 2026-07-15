"""
Login page object for OWASP Juice Shop.

Encapsulates the login page's selectors (from config) and actions
(navigate to login, perform login). Inherits shared behavior from BasePage.
"""

from pages.base_page import BasePage


class LoginPage(BasePage):
    """Page object for the Juice Shop login page."""

    # Path to the login page (Juice Shop uses Angular hash routing)
    LOGIN_PATH = "/#/login"

    def __init__(self, page, config):
        super().__init__(page, config)
        # Pull login selectors from the site config
        login_selectors = config["selectors"]["login"]
        self.email_input = login_selectors["email_input"]
        self.password_input = login_selectors["password_input"]
        self.submit_button = login_selectors["submit_button"]

    def open(self) -> None:
        """Navigate to the login page and dismiss blocking overlays."""
        self.navigate(self.LOGIN_PATH)
        self.dismiss_overlays()

    def login(self, email: str, password: str) -> None:
        """Fill the login form and submit.

        Args:
            email: Email/username to enter.
            password: Password to enter.
        """
        self.page.fill(self.email_input, email)
        self.page.fill(self.password_input, password)
        self.page.click(self.submit_button)

    def login_with_payload(self, email_payload: str, password: str) -> None:
        """Submit the login form with supplied values.

        Both values are provided by the caller — the page object performs
        the submission without assumptions about content or intent.
        """
        self.page.fill(self.email_input, email_payload)
        self.page.fill(self.password_input, password)
        self.page.click(self.submit_button)