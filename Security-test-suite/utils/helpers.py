"""
Helper functions for interacting with OWASP Juice Shop API.

Provides user registration, login, and token management utilities
shared across all test modules.
"""

from __future__ import annotations

import httpx


def register_user(
    client: httpx.Client,
    email: str,
    password: str,
    password_repeat: str | None = None,
    security_question_id: int = 1,
    security_answer: str = "answer",
) -> httpx.Response:
    """Register a new user account on Juice Shop."""
    return client.post(
        "/api/Users/",
        json={
            "email": email,
            "password": password,
            "passwordRepeat": password_repeat or password,
            "securityQuestion": {
                "id": security_question_id,
                "question": "Your eldest siblings middle name?",
            },
            "securityAnswer": security_answer,
        },
    )


def login(client: httpx.Client, email: str, password: str) -> httpx.Response:
    """Authenticate and return the raw response (contains token on success)."""
    return client.post(
        "/rest/user/login",
        json={"email": email, "password": password},
    )


def get_auth_token(client: httpx.Client, email: str, password: str) -> str:
    """Login and return the Bearer token string."""
    resp = login(client, email, password)
    resp.raise_for_status()
    return resp.json()["authentication"]["token"]


def auth_headers(token: str) -> dict[str, str]:
    """Return Authorization header dict for a given token."""
    return {"Authorization": f"Bearer {token}"}


def create_test_user(client: httpx.Client, suffix: str = "") -> dict[str, str]:
    """Register a fresh test user and return {"email", "password", "token"}."""
    import uuid

    uid = uuid.uuid4().hex[:8]
    email = f"test_{uid}{suffix}@test.local"
    password = "Test1234!"
    register_user(client, email, password)
    token = get_auth_token(client, email, password)
    return {"email": email, "password": password, "token": token}
