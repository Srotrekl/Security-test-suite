"""
Shared pytest fixtures for the security test suite.

Provides HTTP clients, authentication tokens, and test user management
used across both API and UI test modules.
"""

from __future__ import annotations

import os
from typing import Generator

import httpx
import pytest
from dotenv import load_dotenv

from config.settings import get_settings
from utils.helpers import create_test_user, get_auth_token, auth_headers

load_dotenv()

settings = get_settings()
BASE_URL = settings.base_url


# ---------------------------------------------------------------------------
# Session-level health checks
# ---------------------------------------------------------------------------


def _wait_for_juice_shop(url: str, retries: int = 10, delay: float = 2.0) -> None:
    """Block until Juice Shop responds or raise after *retries* attempts."""
    import time

    for attempt in range(1, retries + 1):
        try:
            resp = httpx.get(f"{url}/rest/admin/application-version", timeout=5.0)
            if resp.status_code == 200:
                return
        except httpx.ConnectError:
            pass
        if attempt < retries:
            time.sleep(delay)
    pytest.exit(
        f"Juice Shop is not reachable at {url} after {retries} attempts. "
        "Start it with: docker compose up juice-shop -d",
        returncode=1,
    )


def pytest_configure(config: pytest.Config) -> None:
    """Run once before the entire test session — verify services are up."""
    if config.option.collectonly:
        return
    _wait_for_juice_shop(BASE_URL)


# ---------------------------------------------------------------------------
# HTTP client fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def base_url() -> str:
    """Base URL of the Juice Shop instance."""
    return BASE_URL


@pytest.fixture(scope="session")
def client(base_url: str) -> Generator[httpx.Client, None, None]:
    """Session-scoped HTTP client pointed at Juice Shop."""
    with httpx.Client(base_url=base_url, timeout=settings.test_timeout) as c:
        yield c


@pytest.fixture()
def fresh_client(base_url: str) -> Generator[httpx.Client, None, None]:
    """Function-scoped HTTP client for tests that need clean state."""
    with httpx.Client(base_url=base_url, timeout=settings.test_timeout) as c:
        yield c


# ---------------------------------------------------------------------------
# Authentication fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def admin_token(client: httpx.Client) -> str:
    """Admin Bearer token (session-scoped, created once)."""
    return get_auth_token(
        client,
        settings.test_admin_email,
        settings.admin_password_plain,
    )


@pytest.fixture(scope="session")
def admin_headers(admin_token: str) -> dict[str, str]:
    """Authorization headers for admin user."""
    return auth_headers(admin_token)


@pytest.fixture()
def test_user(fresh_client: httpx.Client) -> dict[str, str]:
    """Create a disposable test user and return {email, password, token}."""
    return create_test_user(fresh_client)


@pytest.fixture()
def second_test_user(fresh_client: httpx.Client) -> dict[str, str]:
    """Create a second disposable test user for IDOR tests."""
    return create_test_user(fresh_client, suffix="_victim")
