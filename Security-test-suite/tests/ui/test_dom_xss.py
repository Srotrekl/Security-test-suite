"""
OWASP A03:2021 -- Injection (DOM-based Cross-Site Scripting)

Tests DOM-based XSS vulnerabilities via the Juice Shop search bar.
Unlike reflected XSS (server-side), DOM XSS occurs entirely in the
browser when client-side JavaScript inserts unsanitised user input
into the DOM.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page

from tests.ui.pages.search_page import SearchPage

XSS_SEARCH_PAYLOADS: list[str] = [
    "<iframe src=\"javascript:alert('xss')\">",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert('xss')>",
    "<script>alert('xss')</script>",
    "<<script>alert('xss')//<</script>",
    "<body onload=alert('xss')>",
]


@pytest.mark.ui
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.xss
class TestDOMXSS:
    """DOM-based XSS tests via the search bar."""

    @pytest.mark.parametrize("payload", XSS_SEARCH_PAYLOADS, ids=lambda p: p[:35])
    def test_xss_payload_not_rendered_in_dom(
        self, search_page: SearchPage, payload: str
    ) -> None:
        """Inject an XSS payload through the search bar and verify it is
        not rendered as executable HTML in the DOM.

        The application must HTML-encode or strip dangerous tags before
        inserting search terms into the page. If the raw payload appears
        in ``innerHTML``, the app is vulnerable to DOM XSS.
        """
        search_page.navigate()
        search_page.search(payload)
        search_page.page.wait_for_timeout(1000)

        # Check if the payload was inserted unescaped into the DOM
        body_html = search_page.page.evaluate("() => document.body.innerHTML")
        if payload in body_html:
            pytest.fail(
                f"DOM XSS: payload rendered unescaped in the DOM. "
                f"Payload: {payload!r}"
            )

    def test_xss_script_execution_detected(
        self, search_page: SearchPage
    ) -> None:
        """Use a payload that sets a JS flag on execution and verify
        the flag was NOT set.

        This catches cases where the payload is encoded in the DOM but
        still executes (e.g., via ``eval`` or ``document.write``).
        """
        marker = "__xss_fired__"
        payload = f"<img src=x onerror=\"window.{marker}=true\">"

        search_page.navigate()
        # Pre-set the marker to false so we can detect a change
        search_page.page.evaluate(f"() => {{ window['{marker}'] = false }}")

        search_page.search(payload)
        search_page.page.wait_for_timeout(1500)

        fired = search_page.check_xss_execution(marker)
        if fired:
            pytest.fail(
                "DOM XSS: JavaScript payload executed in the browser. "
                f"Marker '{marker}' was set to true."
            )

    def test_search_result_encodes_special_characters(
        self, search_page: SearchPage
    ) -> None:
        """Search for a string with HTML special characters and verify
        they are entity-encoded in the response.

        Proper encoding converts ``<`` to ``&lt;``, ``>`` to ``&gt;``,
        preventing tag injection.
        """
        payload = '<script>alert("encoded")</script>'
        search_page.navigate()
        search_page.search(payload)
        search_page.page.wait_for_timeout(1000)

        content = search_page.get_page_content()
        # The raw payload should NOT appear; encoded version is acceptable
        if payload in content:
            pytest.fail(
                "Special characters not encoded in search results — "
                "potential DOM XSS vector."
            )
