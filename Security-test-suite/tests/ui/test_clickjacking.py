"""
OWASP A05:2021 -- Security Misconfiguration (Clickjacking)

Tests clickjacking protection by verifying the presence and
correctness of X-Frame-Options and Content-Security-Policy
frame-ancestors directives.  Also attempts to embed Juice Shop
in an iframe to confirm the browser enforces the policy.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page

from config.settings import get_settings


@pytest.mark.ui
@pytest.mark.security
@pytest.mark.headers
class TestClickjacking:
    """Clickjacking protection tests."""

    def test_x_frame_options_header_present(self, page: Page, base_url: str) -> None:
        """Verify that the server sends an X-Frame-Options header.

        Without X-Frame-Options (DENY or SAMEORIGIN), the application
        can be embedded in an attacker-controlled iframe, enabling
        clickjacking attacks that trick users into performing unintended
        actions.
        """
        response = page.goto(base_url)
        assert response is not None, "No response received from Juice Shop"

        xfo = response.headers.get("x-frame-options")
        assert xfo is not None, (
            "Missing X-Frame-Options header — application is vulnerable "
            "to clickjacking."
        )
        assert xfo.upper() in ("DENY", "SAMEORIGIN"), (
            f"X-Frame-Options should be DENY or SAMEORIGIN, got '{xfo}'."
        )

    def test_csp_frame_ancestors_directive(self, page: Page, base_url: str) -> None:
        """Verify that Content-Security-Policy includes frame-ancestors.

        The ``frame-ancestors`` CSP directive is the modern replacement
        for X-Frame-Options and provides more granular control over
        which origins may embed the page.
        """
        response = page.goto(base_url)
        assert response is not None

        csp = response.headers.get("content-security-policy", "")
        if "frame-ancestors" not in csp:
            pytest.fail(
                "CSP header missing 'frame-ancestors' directive. "
                "The modern clickjacking defence is not configured."
            )

    def test_page_refuses_to_load_in_iframe(self, page: Page, base_url: str) -> None:
        """Attempt to embed Juice Shop in an iframe and verify it is blocked.

        Creates a minimal HTML page with an iframe pointing at Juice Shop.
        If the iframe loads successfully, the application lacks clickjacking
        protection at the browser level.
        """
        html = f"""
        <html><body>
        <iframe id="target" src="{base_url}" width="800" height="600"></iframe>
        <script>
            window.__iframeLoaded = false;
            document.getElementById('target').onload = function() {{
                try {{
                    var doc = this.contentDocument || this.contentWindow.document;
                    if (doc && doc.body && doc.body.innerHTML.length > 0) {{
                        window.__iframeLoaded = true;
                    }}
                }} catch(e) {{
                    // Cross-origin error means the frame was blocked — good
                    window.__iframeLoaded = false;
                }}
            }};
        </script>
        </body></html>
        """
        page.set_content(html)
        page.wait_for_timeout(3000)

        loaded = page.evaluate("() => window.__iframeLoaded")
        if loaded:
            pytest.fail(
                "Juice Shop loaded inside an iframe — clickjacking is possible. "
                "X-Frame-Options or CSP frame-ancestors must be configured."
            )
