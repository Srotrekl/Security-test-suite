"""Page Object Model for the Juice Shop search functionality."""

from __future__ import annotations

from playwright.sync_api import Page


class SearchPage:
    """Encapsulates interactions with the Juice Shop search bar."""

    def __init__(self, page: Page, base_url: str) -> None:
        self.page = page
        self.base_url = base_url

    def navigate(self) -> None:
        """Open the Juice Shop home page and dismiss overlays."""
        self.page.goto(f"{self.base_url}/#/")
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

    def open_search(self) -> None:
        """Click the search icon to reveal the search input."""
        self.page.locator("mat-icon", has_text="search").click()

    def search(self, query: str) -> None:
        """Type a query into the search bar and submit."""
        self.open_search()
        search_input = self.page.locator("#mat-input-0")
        # Fallback: try the generic search input if the ID-based one isn't found
        if not search_input.is_visible(timeout=2000):
            search_input = self.page.locator("input[aria-label='Search']")
        search_input.fill(query)
        search_input.press("Enter")

    def get_page_content(self) -> str:
        """Return the full inner HTML of the page body."""
        return self.page.content()

    def check_xss_execution(self, marker: str = "__xss_fired__") -> bool:
        """Evaluate JS in the page context to detect XSS execution.

        Before searching, tests should inject a payload that sets
        ``window.__xss_fired__ = true`` on execution. This method checks
        whether that flag was set.
        """
        result = self.page.evaluate(f"() => !!window['{marker}']")
        return bool(result)
