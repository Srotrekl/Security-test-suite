"""
OWASP A02:2021 -- Cryptographic Failures / Sensitive Data Exposure

Tests for accidental exposure of sensitive information in HTML
comments, JavaScript source, browser console logs, and form
autocomplete attributes.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page

from config.settings import get_settings

SENSITIVE_PATTERNS: list[str] = [
    r"(?i)password\s*[:=]\s*['\"][^'\"]+['\"]",
    r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]",
    r"(?i)secret\s*[:=]\s*['\"][^'\"]+['\"]",
    r"(?i)token\s*[:=]\s*['\"][^'\"]+['\"]",
    r"(?i)private[_-]?key",
    r"(?i)aws[_-]?access",
    r"(?i)jdbc:.*://",
]

COMMENT_PATTERNS: list[str] = [
    r"(?i)<!--.*(?:todo|fixme|hack|password|secret|admin|credential).*-->",
    r"(?i)<!--.*(?:debug|staging|internal).*-->",
]


@pytest.mark.ui
@pytest.mark.security
class TestHTMLComments:
    """Check for sensitive data leaked in HTML comments."""

    def test_no_sensitive_comments_in_html_source(
        self, page: Page, base_url: str
    ) -> None:
        """Scan the main page HTML source for comments containing sensitive
        keywords like TODO, password, secret, admin, debug.

        Developers sometimes leave comments with credentials, internal
        URLs, or debugging notes that aid attackers in reconnaissance.
        """
        page.goto(base_url)
        page.wait_for_load_state("networkidle")
        source = page.content()

        findings: list[str] = []
        for pattern in COMMENT_PATTERNS:
            matches = re.findall(pattern, source)
            findings.extend(matches)

        if findings:
            pytest.fail(
                f"Sensitive HTML comments found ({len(findings)}): "
                f"{findings[:3]!r}"
            )


@pytest.mark.ui
@pytest.mark.security
class TestJavaScriptSecrets:
    """Check for secrets leaked in JavaScript source files."""

    def test_no_secrets_in_js_bundles(self, page: Page, base_url: str) -> None:
        """Intercept JavaScript responses and scan for hardcoded secrets.

        API keys, passwords, and tokens embedded in JS bundles are
        accessible to anyone who views the page source.
        """
        js_contents: list[str] = []

        def capture_js(response: object) -> None:
            """Capture JS response bodies."""
            resp = response  # type: ignore[assignment]
            url: str = resp.url  # type: ignore[attr-defined]
            content_type: str = resp.headers.get("content-type", "")  # type: ignore[attr-defined]
            if ".js" in url or "javascript" in content_type:
                try:
                    body: str = resp.text()  # type: ignore[attr-defined]
                    js_contents.append(body)
                except Exception:
                    pass

        page.on("response", capture_js)
        page.goto(base_url)
        page.wait_for_load_state("networkidle")

        findings: list[str] = []
        for js_body in js_contents:
            for pattern in SENSITIVE_PATTERNS:
                matches = re.findall(pattern, js_body)
                # Filter out common false positives
                for m in matches:
                    if not any(
                        fp in m.lower()
                        for fp in ["placeholder", "example", "your_", "xxx", "change-me"]
                    ):
                        findings.append(m[:80])

        if findings:
            pytest.fail(
                f"Potential secrets found in JS bundles ({len(findings)}): "
                f"{findings[:3]!r}"
            )


@pytest.mark.ui
@pytest.mark.security
class TestConsoleLeaks:
    """Check for sensitive data logged to the browser console."""

    def test_no_sensitive_console_output(self, page: Page, base_url: str) -> None:
        """Capture console.log output and check for sensitive data.

        Developers sometimes leave ``console.log(token)`` or
        ``console.log(user)`` statements that expose credentials
        or session tokens to anyone with DevTools open.
        """
        console_messages: list[str] = []

        page.on("console", lambda msg: console_messages.append(msg.text))

        page.goto(base_url)
        page.wait_for_load_state("networkidle")
        # Navigate a few pages to trigger more console output
        page.goto(f"{base_url}/#/login")
        page.wait_for_load_state("networkidle")

        findings: list[str] = []
        for msg in console_messages:
            for pattern in SENSITIVE_PATTERNS:
                if re.search(pattern, msg):
                    findings.append(msg[:100])

        if findings:
            pytest.fail(
                f"Sensitive data in console output ({len(findings)}): "
                f"{findings[:3]!r}"
            )


@pytest.mark.ui
@pytest.mark.security
class TestAutocompleteAttributes:
    """Check autocomplete settings on sensitive form fields."""

    def test_password_autocomplete_disabled(self, page: Page, base_url: str) -> None:
        """Verify that password fields have autocomplete='off' or
        autocomplete='new-password'.

        If autocomplete is enabled on password fields, browsers may
        store the password in their credential manager, which is a risk
        on shared or public computers.
        """
        page.goto(f"{base_url}/#/login")
        # Dismiss overlays
        for selector in [
            "button[aria-label='Close Welcome Banner']",
            "a[aria-label='dismiss cookie message']",
        ]:
            btn = page.locator(selector)
            if btn.is_visible(timeout=2000):
                btn.click()

        pwd_fields = page.locator("input[type='password']")
        count = pwd_fields.count()

        for i in range(count):
            autocomplete = pwd_fields.nth(i).get_attribute("autocomplete")
            if autocomplete and autocomplete.lower() not in (
                "off",
                "new-password",
                "current-password",
            ):
                pytest.fail(
                    f"Password field #{i} has autocomplete='{autocomplete}'. "
                    "Should be 'off' or 'new-password' on sensitive forms."
                )

    def test_registration_form_autocomplete(self, page: Page, base_url: str) -> None:
        """Check that the registration form does not auto-fill sensitive fields.

        Autocomplete on email + password fields in the registration form
        may leak credentials from other sites via the browser's autofill.
        """
        page.goto(f"{base_url}/#/register")
        # Dismiss overlays
        for selector in [
            "button[aria-label='Close Welcome Banner']",
            "a[aria-label='dismiss cookie message']",
        ]:
            btn = page.locator(selector)
            if btn.is_visible(timeout=2000):
                btn.click()

        page.wait_for_timeout(1000)

        pwd_fields = page.locator("input[type='password']")
        for i in range(pwd_fields.count()):
            autocomplete = pwd_fields.nth(i).get_attribute("autocomplete")
            if autocomplete == "on":
                pytest.fail(
                    f"Registration password field #{i} has autocomplete='on'. "
                    "Browsers may autofill credentials from other sites."
                )
