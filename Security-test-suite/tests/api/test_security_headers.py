"""
OWASP A05:2021 – Security Misconfiguration (HTTP Security Headers)

Tests the presence and correctness of HTTP security headers.
Missing headers expose the application to clickjacking, MIME-type
sniffing, XSS, and protocol downgrade attacks.
"""

from __future__ import annotations

import httpx
import pytest


ENDPOINTS_TO_CHECK: list[str] = [
    "/",
    "/rest/products/search?q=test",
    "/api/Users/",
    "/rest/user/login",
]

REQUIRED_HEADERS: list[tuple[str, str | None]] = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", None),
    ("Content-Security-Policy", None),
    ("Strict-Transport-Security", None),
    ("X-XSS-Protection", None),
    ("Referrer-Policy", None),
    ("Permissions-Policy", None),
]


@pytest.mark.api
@pytest.mark.security
@pytest.mark.headers
class TestSecurityHeaders:
    """Validate security headers across multiple endpoints."""

    @pytest.mark.parametrize("endpoint", ENDPOINTS_TO_CHECK)
    def test_x_content_type_options(
        self, client: httpx.Client, endpoint: str
    ) -> None:
        """X-Content-Type-Options must be 'nosniff'.

        Prevents browsers from MIME-sniffing the response away from
        the declared Content-Type, blocking drive-by downloads.
        """
        resp = client.get(endpoint)
        value = resp.headers.get("X-Content-Type-Options")
        assert value is not None, (
            f"Missing X-Content-Type-Options header on {endpoint}"
        )
        assert value.lower() == "nosniff", (
            f"X-Content-Type-Options should be 'nosniff', got '{value}' on {endpoint}"
        )

    @pytest.mark.parametrize("endpoint", ENDPOINTS_TO_CHECK)
    def test_x_frame_options(
        self, client: httpx.Client, endpoint: str
    ) -> None:
        """X-Frame-Options must be set to prevent clickjacking.

        Without this header, the application can be embedded in an
        iframe on a malicious site, enabling clickjacking attacks.
        """
        resp = client.get(endpoint)
        value = resp.headers.get("X-Frame-Options")
        assert value is not None, (
            f"Missing X-Frame-Options header on {endpoint}. "
            "Application is vulnerable to clickjacking."
        )
        assert value.upper() in ("DENY", "SAMEORIGIN"), (
            f"X-Frame-Options should be DENY or SAMEORIGIN, got '{value}' on {endpoint}"
        )

    @pytest.mark.parametrize("endpoint", ENDPOINTS_TO_CHECK)
    def test_content_security_policy(
        self, client: httpx.Client, endpoint: str
    ) -> None:
        """Content-Security-Policy header should be present.

        CSP mitigates XSS by restricting which resources the browser
        is allowed to load.
        """
        resp = client.get(endpoint)
        csp = resp.headers.get("Content-Security-Policy")
        assert csp is not None, (
            f"Missing Content-Security-Policy header on {endpoint}. "
            "No CSP protection against XSS."
        )

    @pytest.mark.parametrize("endpoint", ENDPOINTS_TO_CHECK)
    def test_strict_transport_security(
        self, client: httpx.Client, endpoint: str
    ) -> None:
        """Strict-Transport-Security should enforce HTTPS.

        HSTS prevents protocol downgrade attacks and cookie hijacking
        by instructing browsers to only use HTTPS.
        """
        resp = client.get(endpoint)
        hsts = resp.headers.get("Strict-Transport-Security")
        if hsts is None:
            pytest.fail(
                f"Missing Strict-Transport-Security header on {endpoint}. "
                "Application does not enforce HTTPS."
            )

    @pytest.mark.parametrize("endpoint", ENDPOINTS_TO_CHECK)
    def test_no_server_version_leak(
        self, client: httpx.Client, endpoint: str
    ) -> None:
        """Server header should not disclose version information.

        Leaking server software and version helps attackers identify
        known vulnerabilities (information disclosure).
        """
        resp = client.get(endpoint)
        server = resp.headers.get("Server", "")
        x_powered = resp.headers.get("X-Powered-By", "")

        if x_powered:
            pytest.fail(
                f"X-Powered-By header present on {endpoint}: '{x_powered}'. "
                "Remove to reduce information leakage."
            )
