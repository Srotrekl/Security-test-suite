"""
OWASP A07:2021 – Identification and Authentication Failures (Rate Limiting)

Tests whether the application enforces rate limiting on sensitive
endpoints. Without rate limiting, attackers can perform brute force
attacks, credential stuffing, and denial of service.
"""

from __future__ import annotations

import time

import httpx
import pytest


@pytest.mark.api
@pytest.mark.security
class TestRateLimiting:
    """Rate limiting and throttling tests."""

    def test_login_rate_limit(self, fresh_client: httpx.Client) -> None:
        """Send 50 rapid login requests — expect HTTP 429 (Too Many Requests).

        Without rate limiting on the login endpoint, attackers can
        perform high-speed brute force and credential stuffing attacks.
        """
        blocked = False
        for i in range(50):
            resp = fresh_client.post(
                "/rest/user/login",
                json={
                    "email": f"ratelimit_{i}@test.local",
                    "password": "wrong",
                },
            )
            if resp.status_code == 429:
                blocked = True
                break

        if not blocked:
            pytest.fail(
                "No rate limiting on /rest/user/login after 50 rapid requests. "
                "Brute force and credential stuffing attacks are possible."
            )

    def test_registration_rate_limit(
        self, fresh_client: httpx.Client
    ) -> None:
        """Send 30 rapid registration requests to detect mass account creation.

        Unrestricted registration allows automated creation of fake
        accounts for spam, abuse, or resource exhaustion.
        """
        blocked = False
        for i in range(30):
            resp = fresh_client.post(
                "/api/Users/",
                json={
                    "email": f"ratelimit_reg_{i}@test.local",
                    "password": "Test1234!",
                    "passwordRepeat": "Test1234!",
                    "securityQuestion": {
                        "id": 1,
                        "question": "Your eldest siblings middle name?",
                    },
                    "securityAnswer": "test",
                },
            )
            if resp.status_code == 429:
                blocked = True
                break

        if not blocked:
            pytest.fail(
                "No rate limiting on /api/Users/ registration endpoint. "
                "Mass account creation is possible."
            )

    def test_password_reset_rate_limit(
        self, fresh_client: httpx.Client
    ) -> None:
        """Send 20 rapid password reset requests.

        Unrestricted password reset enables email bombing and can
        be used to enumerate valid email addresses.
        """
        blocked = False
        for i in range(20):
            resp = fresh_client.post(
                "/rest/user/reset-password",
                json={
                    "email": "admin@juice-sh.op",
                    "answer": f"wrong_{i}",
                    "new": "NewPass123!",
                    "repeat": "NewPass123!",
                },
            )
            if resp.status_code == 429:
                blocked = True
                break

        if not blocked:
            pytest.fail(
                "No rate limiting on password reset endpoint. "
                "Email bombing and brute force of security answers possible."
            )

    def test_product_search_rate_limit(
        self, fresh_client: httpx.Client
    ) -> None:
        """Send 100 rapid search requests to check for DoS protection.

        Unthrottled search endpoints can be abused for resource
        exhaustion or to amplify injection attacks.
        """
        blocked = False
        for i in range(100):
            resp = fresh_client.get(
                "/rest/products/search",
                params={"q": f"test_{i}"},
            )
            if resp.status_code == 429:
                blocked = True
                break

        if not blocked:
            pytest.fail(
                "No rate limiting on search endpoint after 100 requests. "
                "Potential for resource exhaustion."
            )
