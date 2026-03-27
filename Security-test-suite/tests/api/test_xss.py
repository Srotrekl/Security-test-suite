"""
OWASP A03:2021 – Injection (Cross-Site Scripting)

Tests reflected and stored XSS vulnerabilities via Juice Shop API
endpoints. XSS allows attackers to execute arbitrary JavaScript in a
victim's browser, leading to session hijacking, credential theft,
and defacement.
"""

from __future__ import annotations

import httpx
import pytest

from utils.helpers import auth_headers
from utils.payloads import XSS_REFLECTED, XSS_STORED


@pytest.mark.api
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.xss
class TestReflectedXSS:
    """Reflected XSS via search and error endpoints."""

    @pytest.mark.parametrize("payload", XSS_REFLECTED, ids=lambda p: p[:30])
    def test_xss_reflected_in_search(
        self, client: httpx.Client, payload: str
    ) -> None:
        """Inject XSS payload via the search query parameter.

        If the payload appears unescaped in the response body, the
        application is vulnerable to reflected XSS. An attacker can
        craft a malicious URL that executes JavaScript when clicked.
        """
        response = client.get(
            "/rest/products/search", params={"q": payload}
        )
        if payload in response.text:
            pytest.fail(
                f"Reflected XSS: payload echoed unescaped in response. "
                f"Payload: {payload!r}"
            )

    def test_xss_in_error_response(self, client: httpx.Client) -> None:
        """Trigger an error response and check if input is reflected.

        Error pages that reflect user input without escaping are a
        classic reflected XSS vector.
        """
        payload = "<script>alert('xss')</script>"
        response = client.get(f"/rest/products/search?q={payload}")
        if payload in response.text:
            pytest.fail(
                "XSS payload reflected in error response without encoding."
            )


@pytest.mark.api
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.xss
class TestStoredXSS:
    """Stored XSS via user-generated content endpoints."""

    @pytest.mark.parametrize("payload", XSS_STORED[:3], ids=lambda p: p[:30])
    def test_xss_stored_in_product_review(
        self,
        fresh_client: httpx.Client,
        test_user: dict[str, str],
        payload: str,
    ) -> None:
        """Submit an XSS payload as a product review.

        Stored XSS persists in the database and executes every time
        another user views the review — much more dangerous than
        reflected XSS because it does not require victim interaction
        beyond normal browsing.
        """
        headers = auth_headers(test_user["token"])

        # Submit review with XSS payload
        fresh_client.put(
            "/rest/products/1/reviews",
            headers=headers,
            json={"message": payload, "author": test_user["email"]},
        )

        # Read reviews back
        response = fresh_client.get("/rest/products/1/reviews")
        if response.status_code == 200 and payload in response.text:
            pytest.fail(
                f"Stored XSS: payload persisted in product review. "
                f"Payload: {payload!r}"
            )

    def test_xss_stored_in_username(
        self, fresh_client: httpx.Client
    ) -> None:
        """Register with an XSS payload as the username/email.

        If the email is displayed unescaped in admin panels or user
        listings, it triggers stored XSS.
        """
        import uuid

        xss_email = f"<img src=x onerror=alert(1)>{uuid.uuid4().hex[:4]}@test.local"
        response = fresh_client.post(
            "/api/Users/",
            json={
                "email": xss_email,
                "password": "ValidPass123!",
                "passwordRepeat": "ValidPass123!",
                "securityQuestion": {
                    "id": 1,
                    "question": "Your eldest siblings middle name?",
                },
                "securityAnswer": "test",
            },
        )
        if response.status_code == 201:
            body = response.json()
            if "<img" in body.get("data", {}).get("email", ""):
                pytest.fail(
                    "Stored XSS: HTML payload accepted and stored in "
                    "user email field without sanitization."
                )
