# Adding New Tests

This guide explains how to add a new test module to the security test suite.

## Naming Conventions

- **Test files:** `test_<vulnerability_type>.py` (e.g., `test_ssrf.py`)
- **Test classes:** `Test<Category>` (e.g., `TestSSRF`)
- **Test methods:** `test_<what>_<expected>` (e.g., `test_ssrf_internal_url_blocked`)
- **Page objects:** `<PageName>Page` in `tests/ui/pages/<page_name>_page.py`

## Step 1: Add Payloads (if needed)

Add test payloads to `utils/payloads.py`:

```python
# ---------------------------------------------------------------------------
# Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------

SSRF_URLS: list[str] = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
]
```

## Step 2: Create the Test Module

### API Test (`tests/api/test_ssrf.py`)

```python
"""
OWASP A10:2021 -- Server-Side Request Forgery (SSRF)

Tests SSRF vulnerabilities where the application can be tricked
into making requests to internal resources.
"""

from __future__ import annotations

import httpx
import pytest

from utils.payloads import SSRF_URLS


@pytest.mark.api
@pytest.mark.security
class TestSSRF:
    """Server-Side Request Forgery tests."""

    @pytest.mark.parametrize("url", SSRF_URLS)
    def test_ssrf_url_not_fetched(
        self, client: httpx.Client, url: str
    ) -> None:
        """Submit an internal URL and verify the server does not fetch it.

        SSRF allows attackers to make the server send requests to
        internal services, potentially accessing metadata endpoints,
        internal APIs, or local files.
        """
        response = client.post(
            "/profile",
            json={"imageUrl": url},
        )
        # Assert the server did not return content from the internal URL
        assert response.status_code in (400, 403, 422), (
            f"Server may have fetched internal URL: {url}"
        )
```

### UI Test (`tests/ui/test_ssrf.py`)

Follow the same pattern but use Playwright. Always use Page Object Model for page interactions.

## Step 3: Add Markers

Ensure your test class has the required markers:

```python
@pytest.mark.api        # or @pytest.mark.ui
@pytest.mark.security   # all security tests
@pytest.mark.critical   # if high severity
```

If you need a new marker, add it to `pytest.ini`:

```ini
markers =
    ssrf: Server-Side Request Forgery tests
```

## Step 4: Use Existing Fixtures

Available fixtures from `tests/conftest.py`:

| Fixture | Scope | Description |
|---------|-------|-------------|
| `base_url` | session | Juice Shop URL |
| `client` | session | Shared httpx client |
| `fresh_client` | function | Clean httpx client per test |
| `admin_token` | session | Admin JWT token |
| `admin_headers` | session | Admin Authorization headers |
| `test_user` | function | Fresh disposable test user |
| `second_test_user` | function | Second test user (for IDOR tests) |

For UI tests (`tests/ui/conftest.py`):

| Fixture | Scope | Description |
|---------|-------|-------------|
| `browser` | session | Chromium browser instance |
| `context` | function | Isolated browser context |
| `page` | function | New page in context |
| `login_page` | function | LoginPage POM instance |
| `search_page` | function | SearchPage POM instance |
| `authenticated_page` | function | Page logged in as test user |

## Step 5: Write Docstrings

Every test function **must** have a Google-style docstring explaining:

1. **What** the test does (first line)
2. **Why** this is a security risk (paragraph)

```python
def test_example(self, client: httpx.Client) -> None:
    """Short description of what the test does.

    Longer explanation of why this is a security concern,
    what the OWASP category is, and what a successful exploit
    looks like.
    """
```

## Step 6: Run and Verify

```bash
# Run only your new tests
pytest tests/api/test_ssrf.py -v

# Run with your new marker
pytest -m ssrf -v

# Verify HTML report includes the new tests
pytest tests/api/test_ssrf.py --html=reports/report.html --self-contained-html
```

## Checklist

- [ ] Payloads added to `utils/payloads.py` (if needed)
- [ ] Test file created with correct naming
- [ ] Module docstring references OWASP category
- [ ] All test functions have docstrings
- [ ] Type hints on all parameters and return types
- [ ] Markers applied (`api`/`ui`, `security`, optionally `critical`)
- [ ] New marker added to `pytest.ini` (if needed)
- [ ] Tests pass locally
- [ ] No hardcoded credentials
