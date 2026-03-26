# Security Test Suite

Automated security testing suite for OWASP Juice Shop, covering OWASP Top 10 (2021).

## Quick Start

```bash
cp .env.example .env
docker compose up juice-shop -d
pip install -r requirements.txt
playwright install chromium
pytest
```

## Running Tests

```bash
pytest tests/api/ -v       # API tests only
pytest tests/ui/ -v        # UI tests only
pytest -m critical         # Critical findings only
pytest -m sqli             # SQL injection only
```

## Configuration

- `.env` — environment variables (from `.env.example` template)
- `config/settings.py` — typed settings via pydantic-settings
- `pytest.ini` — markers and pytest options

## Project Conventions

- **Language:** English (code, docs, comments)
- **Docstrings:** Google style, required on all test functions
- **Type hints:** Required on all function signatures
- **Markers:** `api`, `ui`, `security`, `critical`, `sqli`, `xss`, `auth`, `idor`, `headers`, `smoke`, `slow`
- **Commits:** Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`)
- **UI tests:** Page Object Model pattern (`tests/ui/pages/`)
- **No hardcoded secrets** — all credentials via `.env`
- **Linting:** ruff + black formatting via pre-commit

## Key Files

| File | Purpose |
|------|---------|
| `tests/conftest.py` | Shared fixtures, health check |
| `tests/ui/conftest.py` | Playwright fixtures, screenshot on failure |
| `utils/payloads.py` | Centralised attack payloads |
| `utils/helpers.py` | API helpers (register, login, tokens) |
| `config/settings.py` | Environment loading and validation |
