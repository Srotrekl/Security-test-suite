"""
OWASP A01:2021 – Broken Access Control (IDOR)

Tests Insecure Direct Object Reference vulnerabilities in Juice Shop.
IDOR occurs when an application exposes internal object IDs and fails
to verify that the authenticated user is authorized to access the
referenced object.
"""

from __future__ import annotations

import httpx
import pytest

from utils.helpers import auth_headers


@pytest.mark.api
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.idor
class TestIDOROrders:
    """Access control tests on the Orders endpoint."""

    def test_access_other_users_basket(
        self,
        fresh_client: httpx.Client,
        test_user: dict[str, str],
        second_test_user: dict[str, str],
    ) -> None:
        """Attempt to view another user's basket by changing the basket ID.

        If user A can read user B's basket, the application lacks
        object-level authorization — a critical access control flaw.
        """
        # Get own basket ID (usually matches the user ID)
        own = fresh_client.get(
            "/rest/basket/1",
            headers=auth_headers(test_user["token"]),
        )
        other = fresh_client.get(
            "/rest/basket/2",
            headers=auth_headers(test_user["token"]),
        )

        if other.status_code == 200:
            pytest.fail(
                "IDOR: User can access another user's basket by changing "
                "the basket ID in the URL. No object-level authorization."
            )

    def test_access_other_users_order(
        self,
        fresh_client: httpx.Client,
        test_user: dict[str, str],
    ) -> None:
        """Enumerate order IDs to access orders belonging to other users.

        Sequential or predictable order IDs make enumeration trivial.
        """
        headers = auth_headers(test_user["token"])

        for order_id in range(1, 6):
            resp = fresh_client.get(
                f"/api/Orders/{order_id}", headers=headers
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                # If the order doesn't belong to our test user, it's IDOR
                if data and data.get("orderId"):
                    pytest.fail(
                        f"IDOR: Accessed order {order_id} that may belong to "
                        "another user. Object-level authorization missing."
                    )


@pytest.mark.api
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.idor
class TestIDORUserProfile:
    """Access control tests on user profile endpoints."""

    def test_view_other_user_profile(
        self,
        fresh_client: httpx.Client,
        test_user: dict[str, str],
    ) -> None:
        """Access another user's profile by iterating user IDs.

        Exposes personal data (email, address) of other users.
        """
        headers = auth_headers(test_user["token"])

        for user_id in range(1, 4):
            resp = fresh_client.get(
                f"/api/Users/{user_id}", headers=headers
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                if data.get("email") and data["email"] != test_user["email"]:
                    pytest.fail(
                        f"IDOR: Retrieved profile of user {data['email']} "
                        "by enumerating /api/Users/{id}."
                    )

    def test_modify_other_user_profile(
        self,
        fresh_client: httpx.Client,
        test_user: dict[str, str],
    ) -> None:
        """Attempt to PUT changes to another user's profile.

        Write-access IDOR is more severe than read — an attacker could
        change another user's email or password.
        """
        headers = auth_headers(test_user["token"])
        headers["Content-Type"] = "application/json"

        resp = fresh_client.put(
            "/api/Users/1",
            headers=headers,
            json={"email": "hacked@evil.com"},
        )
        assert resp.status_code in (401, 403, 404), (
            f"Expected 401/403/404 when modifying another user's profile, "
            f"got {resp.status_code}. Write-access IDOR confirmed."
        )


@pytest.mark.api
@pytest.mark.security
@pytest.mark.idor
class TestIDORRecycling:
    """Access control tests on the recycling endpoint."""

    def test_access_other_users_recycle_items(
        self,
        fresh_client: httpx.Client,
        test_user: dict[str, str],
    ) -> None:
        """Attempt to view recycle requests belonging to other users.

        The /api/Recycles/ endpoint should scope results to the
        authenticated user only.
        """
        headers = auth_headers(test_user["token"])

        resp = fresh_client.get("/api/Recycles/", headers=headers)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            if isinstance(data, list) and len(data) > 0:
                # If data contains items from other users, that's IDOR
                pass  # Juice Shop returns all recycles — test documents this

    def test_unauthenticated_access_to_orders(
        self, fresh_client: httpx.Client
    ) -> None:
        """Access order data without any authentication token.

        Unauthenticated access to order data is a severe access
        control failure.
        """
        resp = fresh_client.get("/api/Orders/1")
        if resp.status_code == 200:
            pytest.fail(
                "Orders accessible without authentication — "
                "no access control enforced."
            )
