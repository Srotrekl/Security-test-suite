"""
OWASP A05:2021 – Security Misconfiguration (CORS)

Tests Cross-Origin Resource Sharing configuration. Misconfigured
CORS policies allow malicious websites to make authenticated requests
on behalf of the victim, stealing data or performing actions.
"""

from __future__ import annotations

import httpx
import pytest

from utils.payloads import CORS_ORIGINS


@pytest.mark.api
@pytest.mark.security
class TestCORSMisconfiguration:
    """CORS policy validation tests."""

    @pytest.mark.parametrize("origin", CORS_ORIGINS)
    def test_cors_rejects_arbitrary_origin(
        self, client: httpx.Client, origin: str
    ) -> None:
        """Send a request with a malicious Origin header.

        The server should NOT reflect arbitrary origins in
        Access-Control-Allow-Origin. Doing so allows any website
        to read authenticated responses.
        """
        response = client.get(
            "/rest/products/search?q=test",
            headers={"Origin": origin},
        )
        acao = response.headers.get("Access-Control-Allow-Origin", "")

        if acao == origin:
            pytest.fail(
                f"CORS misconfiguration: server reflects arbitrary origin '{origin}' "
                "in Access-Control-Allow-Origin. Attacker site can read responses."
            )

    def test_cors_wildcard_with_credentials(
        self, client: httpx.Client
    ) -> None:
        """Check for Access-Control-Allow-Origin: * combined with credentials.

        A wildcard origin with Allow-Credentials: true is a dangerous
        misconfiguration — though browsers block this combination,
        testing documents the server's intent.
        """
        response = client.get(
            "/rest/products/search?q=test",
            headers={"Origin": "http://evil.com"},
        )
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            pytest.fail(
                "CORS: Wildcard origin combined with Allow-Credentials:true. "
                "This is a severe misconfiguration."
            )

    def test_cors_null_origin(self, client: httpx.Client) -> None:
        """Send Origin: null — server should not allow it.

        The 'null' origin comes from sandboxed iframes, data: URIs,
        and redirects. Allowing it opens the door to CORS exploits.
        """
        response = client.get(
            "/rest/products/search?q=test",
            headers={"Origin": "null"},
        )
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        if acao == "null":
            pytest.fail(
                "CORS: Server allows 'null' origin, exploitable via "
                "sandboxed iframes."
            )

    def test_cors_preflight_methods(self, client: httpx.Client) -> None:
        """Send OPTIONS preflight and check allowed methods.

        Overly permissive Access-Control-Allow-Methods (e.g., DELETE, PUT)
        can enable destructive cross-origin operations.
        """
        response = client.options(
            "/api/Users/",
            headers={
                "Origin": "http://evil.com",
                "Access-Control-Request-Method": "DELETE",
            },
        )
        methods = response.headers.get("Access-Control-Allow-Methods", "")
        if "DELETE" in methods.upper():
            pytest.fail(
                f"CORS preflight allows DELETE method: {methods}. "
                "Cross-origin DELETE requests should be restricted."
            )
