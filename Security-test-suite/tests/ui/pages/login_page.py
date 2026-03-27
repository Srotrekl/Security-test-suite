"""Page Object Model for the Juice Shop login page."""

from __future__ import annotations

from playwright.sync_api import Page, expect


class LoginPage:
    """Encapsulates interactions with the Juice Shop login form."""

    URL_PATH = "/#/login"

    def __init__(self, page: Page, base_url: str) -> None:
        self.page = page
        self.base_url = base_url
        self.email_input = page.locator("#email")
        self.password_input = page.locator("#password")
        self.login_button = page.locator("#loginButton")
        self.error_message = page.locator(".error")

    def navigate(self) -> None:
        """Open the login page and dismiss the welcome banner if present."""
        self.page.goto(f"{self.base_url}{self.URL_PATH}")
        # Dismiss cookie/welcome dialogs that may overlay the form
        self._dismiss_dialogs()

    def _dismiss_dialogs(self) -> None:
        """Close any overlay dialogs (welcome banner, cookie notice)."""
        for selector in [
            "button[aria-label='Close Welcome Banner']",
            "a[aria-label='dismiss cookie message']",
        ]:
            btn = self.page.locator(selector)
            if btn.is_visible(timeout=2000):
                btn.click()

    def login(self, email: str, password: str) -> None:
        """Fill in credentials and submit the login form."""
        self.email_input.fill(email)
        self.password_input.fill(password)
        self.login_button.click()

    def get_error_text(self) -> str:
        """Return the visible error message text, or empty string."""
        self.error_message.wait_for(state="visible", timeout=5000)
        return self.error_message.inner_text()

    @property
    def password_field_type(self) -> str | None:
        """Return the ``type`` attribute of the password input."""
        return self.password_input.get_attribute("type")

    @property
    def password_autocomplete(self) -> str | None:
        """Return the ``autocomplete`` attribute of the password input."""
        return self.password_input.get_attribute("autocomplete")
