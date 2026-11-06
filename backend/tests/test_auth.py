"""Password hashing, bearer tokens and the login route (Sohaib: API)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.auth import (
    AuthNotConfiguredError,
    create_token,
    hash_password,
    verify_password,
    verify_token,
)
from tests.conftest import PASSWORD, SECRET

NOW = 1_800_000_000.0


def test_password_hash_roundtrip_and_salting() -> None:
    first, second = hash_password("s3cret-pass"), hash_password("s3cret-pass")
    assert first != second  # fresh salt each time
    assert "s3cret-pass" not in first
    assert verify_password("s3cret-pass", first)
    assert not verify_password("wrong", first)


@pytest.mark.parametrize("stored", ["", "garbage", "md5$a$b", "scrypt$only-two", "scrypt$!$!"])
def test_malformed_stored_hash_never_matches(stored: str) -> None:
    assert not verify_password("anything", stored)


def test_token_roundtrip() -> None:
    token = create_token("alice@example.com", SECRET, now=NOW)
    assert verify_token(token, SECRET, now=NOW + 60) == "alice@example.com"


def test_token_expires() -> None:
    token = create_token("alice@example.com", SECRET, now=NOW)
    assert verify_token(token, SECRET, now=NOW + 9 * 3600) is None


def test_token_rejects_tampering_and_wrong_key() -> None:
    token = create_token("alice@example.com", SECRET, now=NOW)
    payload, sig = token.split(".")
    forged = create_token("mallory@example.com", SECRET, now=NOW).split(".")[0]
    assert verify_token(f"{forged}.{sig}", SECRET, now=NOW) is None
    assert verify_token(token, "another-secret-0123456789", now=NOW) is None
    assert verify_token(payload, SECRET, now=NOW) is None
    assert verify_token("not.a.token", SECRET, now=NOW) is None


def test_empty_secret_refuses_to_sign() -> None:
    with pytest.raises(AuthNotConfiguredError):
        create_token("alice@example.com", "")


def test_login_success_returns_working_token(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"email": " Alice@Example.com ", "password": PASSWORD}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"  # noqa: S105
    assert body["expires_in"] > 0
    ok = client.get("/api/v1/scans", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert ok.status_code == 200


@pytest.mark.parametrize(
    "creds",
    [
        {"email": "alice@example.com", "password": "nope"},
        {"email": "ghost@example.com", "password": PASSWORD},
    ],
)
def test_login_failure_is_generic(client: TestClient, creds: dict[str, str]) -> None:
    response = client.post("/api/v1/auth/login", json=creds)
    assert response.status_code == 401
    assert response.json() == {
        "error": {"code": "invalid_credentials", "message": "invalid email or password"}
    }


def test_login_is_rate_limited_after_repeated_failures(client: TestClient) -> None:
    for _ in range(10):
        client.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "bad"})
    blocked = client.post(
        "/api/v1/auth/login", json={"email": "alice@example.com", "password": PASSWORD}
    )
    assert blocked.status_code == 429
    assert "retry-after" in blocked.headers


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer garbage"},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer"},
    ],
)
def test_protected_routes_need_a_valid_token(client: TestClient, headers: dict[str, str]) -> None:
    response = client.get("/api/v1/scans", headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    assert response.headers["www-authenticate"] == "Bearer"
