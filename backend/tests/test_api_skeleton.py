"""Every 5.8 route exists, needs auth, and always answers in the 5.8 error shape."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

SCAN = "0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d"


def _assert_error_shape(body: object, code: str) -> None:
    assert isinstance(body, dict)
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message"}
    assert body["error"]["code"] == code


def test_healthz_ok(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/api/v1/scans", {"target_url": "https://example.com", "profile": "smoke"}),
        ("GET", "/api/v1/scans", None),
        ("GET", f"/api/v1/scans/{SCAN}", None),
        ("GET", f"/api/v1/scans/{SCAN}/events", None),
        ("GET", f"/api/v1/scans/{SCAN}/findings", None),
        ("GET", f"/api/v1/scans/{SCAN}/evidence/t1__screenshot_1.png", None),
        ("GET", f"/api/v1/scans/{SCAN}/report?format=md", None),
        ("POST", f"/api/v1/scans/{SCAN}/approvals", {"action": "github_issue", "approved": True}),
        ("GET", f"/api/v1/scans/{SCAN}/audit", None),
    ],
)
def test_every_scan_route_requires_auth(
    client: TestClient, method: str, path: str, body: dict[str, object] | None
) -> None:
    response = client.request(method, path, json=body)
    assert response.status_code == 401
    _assert_error_shape(response.json(), "unauthorized")


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", f"/api/v1/scans/{SCAN}"),
        ("GET", f"/api/v1/scans/{SCAN}/events"),
        ("GET", f"/api/v1/scans/{SCAN}/findings"),
        ("GET", f"/api/v1/scans/{SCAN}/evidence/t1__a.png"),
        ("GET", f"/api/v1/scans/{SCAN}/report"),
        ("GET", f"/api/v1/scans/{SCAN}/audit"),
    ],
)
def test_unknown_scan_is_404_in_error_shape(
    client: TestClient, auth: dict[str, str], method: str, path: str
) -> None:
    response = client.request(method, path, headers=auth)
    assert response.status_code == 404
    _assert_error_shape(response.json(), "scan_not_found")


@pytest.mark.parametrize(
    "body",
    [
        {"target_url": "https://example.com", "profile": "deep"},
        {"profile": "smoke"},
        {"target_url": "https://example.com", "profile": "smoke", "extra": 1},
        {"target_url": "https://example.com", "profile": "smoke"},  # no attestation (CR-4)
        {"target_url": "https://example.com", "profile": "smoke", "authorized": False},
    ],
)
def test_create_scan_rejects_bad_body_with_error_shape(
    client: TestClient, auth: dict[str, str], body: dict[str, object]
) -> None:
    response = client.post("/api/v1/scans", json=body, headers=auth)
    assert response.status_code == 422
    _assert_error_shape(response.json(), "validation_error")


def test_approval_rejects_unknown_action(client: TestClient, auth: dict[str, str]) -> None:
    response = client.post(
        f"/api/v1/scans/{SCAN}/approvals", json={"action": "deploy", "approved": True}, headers=auth
    )
    assert response.status_code == 422
    _assert_error_shape(response.json(), "validation_error")


def test_unknown_route_uses_error_shape(client: TestClient) -> None:
    response = client.get("/api/v1/nope")
    assert response.status_code == 404
    _assert_error_shape(response.json(), "http_404")


def test_bad_report_format_rejected(client: TestClient, auth: dict[str, str]) -> None:
    response = client.get(f"/api/v1/scans/{SCAN}/report?format=docx", headers=auth)
    assert response.status_code == 422
