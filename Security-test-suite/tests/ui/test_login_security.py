"""
OWASP A04:2021 -- Insecure Design / A07:2021 -- Auth Failures

Tests login form security controls via the browser, including
password field masking, user enumeration via error messages,
brute-force protection, and session invalidation after logout.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page

from tests.ui.pages.login_page import LoginPage


@pytest.mark.ui
@pytest.mark.security
@pytest.mark.auth
class TestLoginFormSecurity:
    """Login form security controls."""

    def test_password_field_is_masked(self, login_page: LoginPage) -> None:
        """Verify that the password input has type='password'.

        A missing type attribute (or type='text') exposes the password
        on screen, enabling shoulder-surfing attacks.
        """
        login_page.navigate()
        assert login_page.password_field_type == "password", (
            "Password field is not type='password' — credentials are "
            "visible on screen."
        )

    def test_error_message_does_not_reveal_user_existence(
        self, login_page: LoginPage
    ) -> None:
        """Submit invalid credentials and verify the error message is generic.

        If the app returns different messages for 'user not found' vs
        'wrong password', an attacker can enumerate valid email addresses.
        """
        login_page.navigate()

        # Non-existent user
        login_page.login("nonexistent_user_xyz@fake.local", "WrongPass1!")
        error_nonexistent = login_page.get_error_text()

        login_page.navigate()

        # Existing user, wrong password
        login_page.login("admin@juice-sh.op", "WrongPass1!")
        error_wrong_password = login_page.get_error_text()

        assert error_nonexistent == error_wrong_password, (
            f"Different error messages for existing vs non-existing user: "
            f"'{error_nonexistent}' vs '{error_wrong_password}'. "
            "This enables username enumeration."
        )

    def test_brute_force_lockout_via_ui(self, login_page: LoginPage) -> None:
        """Attempt 10 rapid login failures and check for lockout or rate limiting.

        Without lockout/rate limiting, an attacker can automate password
        guessing through the UI.
        """
        login_page.navigate()
        blocked = False

        for i in range(10):
            login_page.login("admin@juice-sh.op", f"wrong_{i}")
            login_page.page.wait_for_timeout(200)

            # Check for any lockout indication
            content = login_page.page.content().lower()
            if any(kw in content for kw in ["too many", "locked", "rate limit", "429"]):
                blocked = True
                break

            # Re-navigate if needed
            if login_page.page.url and "login" not in login_page.page.url:
                login_page.navigate()

        if not blocked:
            pytest.fail(
                "No lockout or rate limiting after 10 failed login attempts "
                "through the UI. Brute force is possible."
            )

    def test_session_invalidated_after_logout(
        self, authenticated_page: Page, base_url: str
    ) -> None:
        """After logout, navigating to a protected page should redirect to login.

        If the session token is not invalidated server-side, the browser
        can still access protected resources using cached credentials.
        """
        page = authenticated_page

        # Click the account menu and logout
        page.locator("#navbarAccount").click()
        logout_btn = page.locator(
            "button[aria-label='Show the shopping cart']"
        ).or_(page.locator("button", has_text="Logout"))
        if logout_btn.is_visible(timeout=3000):
            logout_btn.click()

        page.wait_for_timeout(1000)

        # Try to access a protected page
        page.goto(f"{base_url}/#/basket")
        page.wait_for_timeout(2000)

        # Should be redirected to login
        if "login" not in page.url and "basket" in page.url:
            # Check if the page actually shows basket content
            content = page.content()
            if "Your Basket" in content or "Total Price" in content:
                pytest.fail(
                    "Protected page accessible after logout — "
                    "session was not properly invalidated."
                )


@pytest.mark.ui
@pytest.mark.security
@pytest.mark.auth
class TestCSRFProtection:
    """CSRF and form security tests."""

    def test_login_form_has_csrf_or_token_protection(
        self, login_page: LoginPage
    ) -> None:
        """Check whether the login form includes CSRF protection.

        Modern SPAs typically use JWT or SameSite cookies instead of
        traditional CSRF tokens. This test documents the mechanism in use.
        Note: Juice Shop is an Angular SPA using JWT, so a traditional
        CSRF token may not be present — the test documents this finding.
        """
        login_page.navigate()
        page = login_page.page

        # Look for hidden CSRF token inputs
        csrf_input = page.locator("input[name*='csrf'], input[name*='_token']")
        # Look for meta tag CSRF token
        csrf_meta = page.locator("meta[name*='csrf']")

        has_csrf = csrf_input.count() > 0 or csrf_meta.count() > 0

        if not has_csrf:
            # Check for SameSite cookie attribute as alternative protection
            cookies = page.context.cookies()
            samesite_cookies = [
                c for c in cookies
                if c.get("sameSite", "").lower() in ("strict", "lax")
            ]
            if not samesite_cookies:
                pytest.fail(
                    "No CSRF token found in login form and no SameSite cookies "
                    "detected. Application may be vulnerable to CSRF attacks."
                )
