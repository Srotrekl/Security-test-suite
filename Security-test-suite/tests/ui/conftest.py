"""
Shared Playwright fixtures for UI security tests.

Provides browser and page instances, authenticated sessions,
and automatic screenshot capture on test failure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

import pytest
from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright

from config.settings import get_settings
from tests.ui.pages.login_page import LoginPage
from tests.ui.pages.search_page import SearchPage

SCREENSHOT_DIR = Path("reports/screenshots")


# ---------------------------------------------------------------------------
# Browser lifecycle
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def browser() -> Generator[Browser, None, None]:
    """Launch a Chromium browser instance (session-scoped)."""
    settings = get_settings()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=settings.headless)
        yield browser
        browser.close()


@pytest.fixture()
def context(browser: Browser) -> Generator[BrowserContext, None, None]:
    """Create a fresh browser context per test (isolated cookies/storage)."""
    ctx = browser.new_context(ignore_https_errors=True)
    yield ctx
    ctx.close()


@pytest.fixture()
def page(context: BrowserContext) -> Page:
    """Create a new page in the current browser context."""
    return context.new_page()


# ---------------------------------------------------------------------------
# Page Object fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def login_page(page: Page, base_url: str) -> LoginPage:
    """Return a LoginPage POM instance."""
    return LoginPage(page, base_url)


@pytest.fixture()
def search_page(page: Page, base_url: str) -> SearchPage:
    """Return a SearchPage POM instance."""
    return SearchPage(page, base_url)


# ---------------------------------------------------------------------------
# Authenticated page
# ---------------------------------------------------------------------------


@pytest.fixture()
def authenticated_page(
    page: Page,
    base_url: str,
) -> Page:
    """Return a page logged in as a fresh test user."""
    from utils.helpers import create_test_user

    import httpx

    with httpx.Client(base_url=base_url, timeout=15.0) as client:
        user = create_test_user(client)

    lp = LoginPage(page, base_url)
    lp.navigate()
    lp.login(user["email"], user["password"])
    page.wait_for_url("**/search**", timeout=10000)
    return page


# ---------------------------------------------------------------------------
# Screenshot on failure
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _screenshot_on_failure(request: pytest.FixtureRequest, page: Page) -> Generator[None, None, None]:
    """Capture a screenshot if the test fails."""
    yield
    if request.node.rep_call and request.node.rep_call.failed:
        SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
        name = request.node.nodeid.replace("::", "_").replace("/", "_")
        page.screenshot(path=str(SCREENSHOT_DIR / f"{name}.png"))


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item) -> Generator[None, None, None]:
    """Store test outcome on the item so fixtures can read it."""
    import pluggy

    outcome: pluggy.Result = yield  # type: ignore[assignment]
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)
