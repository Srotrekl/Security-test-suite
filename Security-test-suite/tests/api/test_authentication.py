"""
OWASP A07:2021 – Identification and Authentication Failures

Tests authentication weaknesses in OWASP Juice Shop including
weak password policies, brute force susceptibility, JWT manipulation,
and session invalidation after logout.
"""

from __future__ import annotations

import json
import time
import base64

import httpx
import pytest

from utils.helpers import register_user, login, auth_headers
from utils.payloads import WEAK_PASSWORDS, COMMON_CREDENTIALS


@pytest.mark.api
@pytest.mark.security
@pytest.mark.auth
class TestWeakPasswords:
    """Password policy enforcement tests."""

    @pytest.mark.parametrize("password", WEAK_PASSWORDS, ids=lambda p: repr(p))
    def test_registration_rejects_weak_password(
        self, fresh_client: httpx.Client, password: str
    ) -> None:
        """Registration should reject passwords that are too short or empty.

        Allowing trivially weak passwords enables credential stuffing and
        brute force attacks. A minimum password complexity policy is a
        basic authentication control.
        """
        import uuid

        email = f"weakpwd_{uuid.uuid4().hex[:6]}@test.local"
        response = register_user(fresh_client, email, password)

        if response.status_code == 201:
            pytest.fail(
                f"Weak password accepted: {password!r}. "
                "Application lacks minimum password policy."
            )


@pytest.mark.api
@pytest.mark.security
@pytest.mark.auth
class TestBruteForce:
    """Account lockout and rate limiting on login."""

    def test_brute_force_no_lockout(self, fresh_client: httpx.Client) -> None:
        """Send 20 rapid login attempts — account should lock after ~5 failures.

        Without account lockout, an attacker can try unlimited password
        combinations until they succeed (credential brute force).
        """
        target_email = "admin@juice-sh.op"
        failure_count = 0

        for i in range(20):
            resp = login(fresh_client, target_email, f"wrong_password_{i}")
            if resp.status_code == 401:
                failure_count += 1
            elif resp.status_code == 429:
                # Rate limiting kicked in — good
                return

        if failure_count >= 20:
            pytest.fail(
                f"All {failure_count} login attempts allowed without lockout or "
                "rate limiting. Brute force attack is possible."
            )


@pytest.mark.api
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.auth
class TestJWTManipulation:
    """JWT token integrity and validation tests."""

    def test_jwt_none_algorithm(
        self, fresh_client: httpx.Client, test_user: dict[str, str]
    ) -> None:
        """Replace JWT algorithm with 'none' and remove the signature.

        The 'none' algorithm attack bypasses signature verification,
        allowing an attacker to forge arbitrary tokens and impersonate
        any user, including admin.
        """
        token = test_user["token"]
        parts = token.split(".")
        # Decode header, change alg to 'none'
        header = json.loads(
            base64.urlsafe_b64decode(parts[0] + "==")
        )
        header["alg"] = "none"
        forged_header = (
            base64.urlsafe_b64encode(json.dumps(header).encode())
            .rstrip(b"=")
            .decode()
        )
        forged_token = f"{forged_header}.{parts[1]}."

        response = fresh_client.get(
            "/rest/user/whoami",
            headers=auth_headers(forged_token),
        )
        if response.status_code == 200:
            user = response.json().get("user", {})
            if user.get("email"):
                pytest.fail(
                    "CRITICAL: JWT 'none' algorithm accepted — "
                    "attacker can forge tokens for any user."
                )

    def test_jwt_tampered_role(
        self, fresh_client: httpx.Client, test_user: dict[str, str]
    ) -> None:
        """Modify the JWT payload to escalate role to 'admin'.

        If the server trusts the payload without verifying the signature,
        a regular user can gain admin privileges.
        """
        token = test_user["token"]
        parts = token.split(".")
        payload = json.loads(
            base64.urlsafe_b64decode(parts[1] + "==")
        )
        payload["data"]["role"] = "admin"
        forged_payload = (
            base64.urlsafe_b64encode(json.dumps(payload).encode())
            .rstrip(b"=")
            .decode()
        )
        forged_token = f"{parts[0]}.{forged_payload}.{parts[2]}"

        response = fresh_client.get(
            "/rest/user/whoami",
            headers=auth_headers(forged_token),
        )
        if response.status_code == 200:
            user = response.json().get("user", {})
            if user.get("role") == "admin":
                pytest.fail(
                    "CRITICAL: Tampered JWT accepted — role escalated to admin."
                )

    def test_jwt_expired_token_rejected(
        self, fresh_client: httpx.Client, test_user: dict[str, str]
    ) -> None:
        """Modify JWT expiry to a past date — server must reject it.

        Accepting expired tokens allows session reuse after intended
        expiration, undermining session lifecycle controls.
        """
        token = test_user["token"]
        parts = token.split(".")
        payload = json.loads(
            base64.urlsafe_b64decode(parts[1] + "==")
        )
        payload["exp"] = 1000000000  # 2001-09-09
        forged_payload = (
            base64.urlsafe_b64encode(json.dumps(payload).encode())
            .rstrip(b"=")
            .decode()
        )
        forged_token = f"{parts[0]}.{forged_payload}.{parts[2]}"

        response = fresh_client.get(
            "/rest/user/whoami",
            headers=auth_headers(forged_token),
        )
        assert response.status_code == 401, (
            f"Expected 401 for expired JWT, got {response.status_code}. "
            "Server accepts expired tokens."
        )


@pytest.mark.api
@pytest.mark.security
@pytest.mark.auth
class TestSessionManagement:
    """Session lifecycle tests."""

    def test_token_valid_after_logout(
        self, fresh_client: httpx.Client, test_user: dict[str, str]
    ) -> None:
        """After logout the token should be invalidated server-side.

        If the server does not maintain a token blacklist, stolen tokens
        remain usable even after the user has logged out.
        """
        token = test_user["token"]
        headers = auth_headers(token)

        # Verify token works before logout
        pre = fresh_client.get("/rest/user/whoami", headers=headers)
        assert pre.status_code == 200, "Token should be valid before logout"

        # Perform logout
        fresh_client.get("/rest/saveLoginIp", headers=headers)

        # Check if token still works
        post = fresh_client.get("/rest/user/whoami", headers=headers)
        if post.status_code == 200:
            pytest.fail(
                "Token still valid after logout — server does not "
                "invalidate sessions (no token blacklist)."
            )

    @pytest.mark.parametrize(
        "cred",
        COMMON_CREDENTIALS,
        ids=lambda c: c["email"],
    )
    def test_default_credentials(
        self, client: httpx.Client, cred: dict[str, str]
    ) -> None:
        """Test whether known default credentials work.

        Default and well-known credentials left in production are a
        common finding in security assessments. Juice Shop ships with
        several seeded accounts.
        """
        response = login(client, cred["email"], cred["password"])
        if response.status_code == 200:
            pytest.fail(
                f"Default credentials work for {cred['email']} — "
                "account should be disabled or password changed."
            )
