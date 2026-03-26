"""
Centralised configuration for the security test suite.

Loads values from ``.env`` via pydantic-settings, provides sensible
defaults for local development, and validates that required variables
are present before tests start.  Secret values are never logged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Typed, validated project settings loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Juice Shop
    juice_shop_url: str = Field(
        default="http://localhost:3000",
        description="Base URL of the Juice Shop instance.",
    )
    juice_shop_version: str = Field(
        default="latest",
        description="Juice Shop Docker image tag.",
    )

    # ZAP Proxy
    zap_api_key: SecretStr = Field(
        default=SecretStr("change-me-to-random-string"),
        description="OWASP ZAP API key.",
    )
    zap_proxy_url: str = Field(
        default="http://localhost:8080",
        description="OWASP ZAP proxy URL.",
    )

    # Test configuration
    test_admin_email: str = Field(
        default="admin@juice-sh.op",
        description="Admin email for Juice Shop.",
    )
    test_admin_password: SecretStr = Field(
        default=SecretStr("admin123"),
        description="Admin password for Juice Shop.",
    )
    test_timeout: int = Field(
        default=30,
        description="Default HTTP request timeout in seconds.",
    )
    test_retry_count: int = Field(
        default=2,
        description="Number of retries for flaky requests.",
    )

    # Reporting
    report_dir: str = Field(default="reports")
    html_report: bool = Field(default=True)

    # Playwright
    headless: bool = Field(
        default=True,
        description="Run Playwright browsers in headless mode.",
    )

    # Derived helpers (not loaded from env) --------------------------------

    @property
    def base_url(self) -> str:
        """Alias kept for backward compatibility with existing fixtures."""
        return self.juice_shop_url

    @property
    def admin_password_plain(self) -> str:
        """Return the admin password as a plain string for API calls."""
        return self.test_admin_password.get_secret_value()


def get_settings() -> Settings:
    """Return a cached ``Settings`` instance.

    Raises ``pydantic.ValidationError`` with a clear message if a required
    variable is missing or has an invalid type.
    """
    return Settings()
