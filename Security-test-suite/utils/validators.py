"""
Validation helpers for security test assertions.

Centralizes common checks so test files stay concise and consistent.
"""

from __future__ import annotations

import httpx

from utils.payloads import REQUIRED_SECURITY_HEADERS


def assert_status(response: httpx.Response, expected: int, context: str = "") -> None:
    """Assert HTTP status code with a clear security-focused message."""
    actual = response.status_code
    assert actual == expected, (
        f"Expected HTTP {expected} but got {actual}. {context}"
    )


def assert_no_sqli_bypass(response: httpx.Response) -> None:
    """Assert that a login response does NOT contain a valid auth token."""
    body = response.json() if response.status_code == 200 else {}
    token = body.get("authentication", {}).get("token")
    assert token is None, (
        "SQL injection bypassed authentication — received a valid token"
    )


def check_security_headers(
    response: httpx.Response,
) -> list[str]:
    """Return a list of missing or misconfigured security headers."""
    issues: list[str] = []
    for header, expected_value in REQUIRED_SECURITY_HEADERS.items():
        actual = response.headers.get(header)
        if actual is None:
            issues.append(f"Missing header: {header}")
        elif expected_value and actual.lower() != expected_value.lower():
            issues.append(
                f"Header {header}: expected '{expected_value}', got '{actual}'"
            )
    return issues


def response_contains_payload(response: httpx.Response, payload: str) -> bool:
    """Check whether an XSS payload appears unescaped in the response body."""
    return payload in response.text
