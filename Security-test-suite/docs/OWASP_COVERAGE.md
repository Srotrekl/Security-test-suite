# OWASP Top 10 (2021) — Test Coverage

Detailed mapping of each OWASP Top 10 category to the tests in this suite. For each category: what we test, how, and what is out of scope.

---

## A01:2021 — Broken Access Control

**Status:** Covered
**Test module:** `tests/api/test_idor.py`

| Test | What it checks |
|------|---------------|
| `test_access_other_users_basket` | Basket IDOR — read another user's basket by changing the ID |
| `test_access_other_users_order` | Order enumeration — iterate order IDs to access other users' orders |
| `test_view_other_user_profile` | User profile IDOR — enumerate /api/Users/{id} |
| `test_modify_other_user_profile` | Write-access IDOR — PUT to another user's profile |
| `test_unauthenticated_access_to_orders` | No-auth access to order endpoints |

**Not tested:** Horizontal privilege escalation between admin roles, path traversal, CORS-based access control bypass (covered in A05).

**Reference:** [OWASP A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

## A02:2021 — Cryptographic Failures

**Status:** Covered (UI)
**Test module:** `tests/ui/test_sensitive_data_exposure.py`

| Test | What it checks |
|------|---------------|
| `test_no_sensitive_comments_in_html_source` | HTML comments with passwords, secrets, debug info |
| `test_no_secrets_in_js_bundles` | API keys, tokens, credentials in JavaScript files |
| `test_no_sensitive_console_output` | Sensitive data leaked via console.log |
| `test_password_autocomplete_disabled` | Autocomplete on password fields |
| `test_registration_form_autocomplete` | Autofill on registration form |

**Not tested:** TLS configuration, cipher suite strength, certificate validation, data-at-rest encryption.

**Reference:** [OWASP A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

## A03:2021 — Injection

**Status:** Covered (API + UI)
**Test modules:** `test_sql_injection.py`, `test_xss.py`, `test_dom_xss.py`

| Test | What it checks |
|------|---------------|
| `test_sql_injection_login_bypass` | 8 SQLi payloads against login endpoint |
| `test_sql_injection_login_admin_bypass` | Admin login bypass via comment injection |
| `test_sql_injection_login_returns_error_message` | SQL error message leakage |
| `test_sql_injection_search_endpoint` | 5 SQLi payloads against product search |
| `test_search_union_extracts_user_data` | UNION-based user data extraction |
| `test_xss_reflected_in_search` | 7 reflected XSS payloads via search |
| `test_xss_in_error_response` | XSS in error pages |
| `test_xss_stored_in_product_review` | Stored XSS in product reviews |
| `test_xss_stored_in_username` | Stored XSS via email/username field |
| `test_xss_payload_not_rendered_in_dom` | DOM XSS via search bar (browser) |
| `test_xss_script_execution_detected` | JS execution detection via marker flag |
| `test_search_result_encodes_special_characters` | HTML entity encoding in search results |

**Not tested:** NoSQL injection, LDAP injection, OS command injection, template injection.

**Reference:** [OWASP A03:2021](https://owasp.org/Top10/A03_2021-Injection/)

---

## A04:2021 — Insecure Design

**Status:** Partially covered
**Test module:** `tests/ui/test_login_security.py`

| Test | What it checks |
|------|---------------|
| `test_error_message_does_not_reveal_user_existence` | Username enumeration via error message differentiation |
| `test_login_form_has_csrf_or_token_protection` | CSRF protection mechanism |

**Not tested:** Business logic flaws, missing fraud controls, insufficient rate limiting on business operations.

**Reference:** [OWASP A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/)

---

## A05:2021 — Security Misconfiguration

**Status:** Covered (API + UI)
**Test modules:** `test_security_headers.py`, `test_cors.py`, `test_clickjacking.py`

| Test | What it checks |
|------|---------------|
| `test_x_content_type_options` | X-Content-Type-Options: nosniff |
| `test_x_frame_options` | X-Frame-Options presence |
| `test_content_security_policy` | CSP header presence |
| `test_strict_transport_security` | HSTS enforcement |
| `test_no_server_version_leak` | X-Powered-By / Server version disclosure |
| `test_cors_rejects_arbitrary_origin` | CORS origin reflection |
| `test_cors_wildcard_with_credentials` | Wildcard + credentials combo |
| `test_cors_null_origin` | Null origin acceptance |
| `test_cors_preflight_methods` | Overly permissive preflight methods |
| `test_x_frame_options_header_present` | Clickjacking — X-Frame-Options (browser) |
| `test_csp_frame_ancestors_directive` | Clickjacking — CSP frame-ancestors |
| `test_page_refuses_to_load_in_iframe` | Iframe embedding test (browser) |

**Not tested:** Directory listing, default error pages, unnecessary HTTP methods, S3 bucket misconfig.

**Reference:** [OWASP A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

## A06:2021 — Vulnerable and Outdated Components

**Status:** Not directly tested

Component vulnerability scanning is best handled by dedicated tools (OWASP Dependency-Check, Snyk, npm audit). The ZAP baseline scan in `docker-compose.yml` provides some coverage.

**Reference:** [OWASP A06:2021](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

---

## A07:2021 — Identification and Authentication Failures

**Status:** Covered
**Test modules:** `test_authentication.py`, `test_rate_limiting.py`, `test_login_security.py`

| Test | What it checks |
|------|---------------|
| `test_registration_rejects_weak_password` | 6 weak password payloads |
| `test_brute_force_no_lockout` | 20 rapid login failures — no lockout |
| `test_jwt_none_algorithm` | JWT 'none' algorithm bypass |
| `test_jwt_tampered_role` | JWT role escalation |
| `test_jwt_expired_token_rejected` | Expired JWT acceptance |
| `test_token_valid_after_logout` | Session invalidation after logout |
| `test_default_credentials` | 5 known default accounts |
| `test_login_rate_limit` | 50 rapid login requests |
| `test_registration_rate_limit` | 30 rapid registration requests |
| `test_password_reset_rate_limit` | 20 rapid password reset requests |
| `test_product_search_rate_limit` | 100 rapid search requests |
| `test_password_field_is_masked` | Password input type='password' |
| `test_brute_force_lockout_via_ui` | UI brute force lockout |
| `test_session_invalidated_after_logout` | Session invalidation (browser) |

**Reference:** [OWASP A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

## A08:2021 — Software and Data Integrity Failures

**Status:** Partially covered
**Test module:** `test_authentication.py` (JWT manipulation)

JWT tests cover token integrity: 'none' algorithm, payload tampering, and signature bypass. These are direct tests of data integrity in authentication tokens.

**Not tested:** CI/CD pipeline integrity, unsigned updates, deserialisation attacks.

**Reference:** [OWASP A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

---

## A09:2021 — Security Logging & Monitoring Failures

**Status:** Indirectly covered
**Test module:** `test_rate_limiting.py`

The absence of rate limiting implies missing request monitoring. These tests document the detection gap.

**Not tested:** Log file content, alerting mechanisms, audit trail completeness.

**Reference:** [OWASP A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)

---

## A10:2021 — Server-Side Request Forgery (SSRF)

**Status:** Not tested

SSRF testing requires specific application functionality (URL fetching, webhook configuration). Juice Shop has limited SSRF surface.

**Reference:** [OWASP A10:2021](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

---

## Coverage Summary

| Category | Coverage |
|----------|----------|
| A01 Broken Access Control | Full |
| A02 Cryptographic Failures | Partial (client-side) |
| A03 Injection | Full (SQLi + XSS + DOM XSS) |
| A04 Insecure Design | Partial |
| A05 Security Misconfiguration | Full |
| A06 Vulnerable Components | ZAP only |
| A07 Auth Failures | Full |
| A08 Data Integrity | Partial (JWT) |
| A09 Logging & Monitoring | Indirect |
| A10 SSRF | Not covered |
