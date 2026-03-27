"""
OWASP A03:2021 – Injection (SQL Injection)

Tests SQL injection vulnerabilities in OWASP Juice Shop's login
and product search endpoints. A secure application must sanitize
all user input and use parameterized queries to prevent injection.
"""

from __future__ import annotations

import httpx
import pytest

from utils.payloads import SQLI_LOGIN_BYPASS, SQLI_SEARCH


@pytest.mark.api
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.sqli
class TestSQLInjectionLogin:
    """SQL injection attacks against the authentication endpoint."""

    @pytest.mark.parametrize("payload", SQLI_LOGIN_BYPASS, ids=lambda p: p[:30])
    def test_sql_injection_login_bypass(
        self, client: httpx.Client, payload: str
    ) -> None:
        """Inject SQL via the email field to bypass authentication.

        A successful injection returns HTTP 200 with a valid JWT token,
        granting access without knowing the password. This is a critical
        vulnerability allowing full account takeover.
        """
        response = client.post(
            "/rest/user/login",
            json={"email": payload, "password": "irrelevant"},
        )

        if response.status_code == 200:
            token = response.json().get("authentication", {}).get("token")
            assert token is None, (
                f"CRITICAL: SQL injection bypassed login with payload: {payload!r}. "
                f"Received valid auth token — full authentication bypass."
            )

    def test_sql_injection_login_admin_bypass(
        self, client: httpx.Client
    ) -> None:
        """Attempt to log in as admin using comment-based SQL injection.

        The payload admin'-- comments out the password check in a
        vulnerable SQL query like:
        SELECT * FROM Users WHERE email='<input>' AND password='<input>'
        """
        response = client.post(
            "/rest/user/login",
            json={"email": "admin@juice-sh.op'--", "password": "anything"},
        )

        if response.status_code == 200:
            data = response.json().get("authentication", {})
            assert data.get("token") is None, (
                "CRITICAL: Admin login bypassed via SQL injection (admin'--)."
            )

    def test_sql_injection_login_returns_error_message(
        self, client: httpx.Client
    ) -> None:
        """Verify that SQL errors are not leaked to the client.

        Exposing SQL error messages aids attackers in refining injection
        payloads (information disclosure).
        """
        response = client.post(
            "/rest/user/login",
            json={"email": "' UNION SELECT 1,2,3--", "password": "x"},
        )
        body = response.text.lower()
        sql_keywords = ["sqlite", "sql syntax", "unrecognized token", "sequelize"]
        leaked = [kw for kw in sql_keywords if kw in body]
        assert not leaked, (
            f"SQL error details leaked in response: {leaked}. "
            "This helps attackers fingerprint the database."
        )


@pytest.mark.api
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.sqli
class TestSQLInjectionSearch:
    """SQL injection attacks against the product search endpoint."""

    @pytest.mark.parametrize("payload", SQLI_SEARCH, ids=lambda p: p[:40])
    def test_sql_injection_search_endpoint(
        self, client: httpx.Client, payload: str
    ) -> None:
        """Inject SQL via the search query parameter.

        A UNION-based injection can exfiltrate data from other tables
        (e.g., user credentials). Time-based blind injection confirms
        the backend executes injected SQL.
        """
        response = client.get(
            "/rest/products/search", params={"q": payload}
        )

        if response.status_code == 200:
            data = response.json().get("data", [])
            # If injection returns significantly more results than a normal
            # search, it likely succeeded.
            normal = client.get(
                "/rest/products/search", params={"q": "apple"}
            )
            normal_count = len(normal.json().get("data", []))
            if len(data) > normal_count + 5:
                pytest.fail(
                    f"CRITICAL: Search SQLi returned {len(data)} results "
                    f"(normal: {normal_count}). Payload: {payload!r}"
                )

    def test_search_union_extracts_user_data(
        self, client: httpx.Client
    ) -> None:
        """Attempt UNION SELECT to extract user emails and password hashes.

        If the response contains email-like strings from the Users table,
        the injection was successful and user data is exposed.
        """
        payload = (
            "qwert')) UNION SELECT id,email,password,'4','5','6','7','8','9' "
            "FROM Users--"
        )
        response = client.get(
            "/rest/products/search", params={"q": payload}
        )

        if response.status_code == 200:
            text = response.text
            if "@juice-sh.op" in text:
                pytest.fail(
                    "CRITICAL: UNION injection extracted user data from the "
                    "Users table via the search endpoint."
                )
