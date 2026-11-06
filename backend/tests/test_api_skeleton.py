"""The API skeleton serves every 5.8 route and always answers in the 5.8 error shape."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
SCAN = "0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d"


def _assert_error_shape(body: object, code: str) -> None:
    assert isinstance(body, dict)
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message"}
    assert body["error"]["code"] == code


def test_healthz_ok() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/api/v1/auth/login", None),
        ("POST", "/api/v1/scans", {"target_url": "https://example.com", "profile": "smoke"}),
        ("GET", "/api/v1/scans", None),
        ("GET", f"/api/v1/scans/{SCAN}", None),
        ("GET", f"/api/v1/scans/{SCAN}/events", None),
        ("GET", f"/api/v1/scans/{SCAN}/findings", None),
        ("GET", f"/api/v1/scans/{SCAN}/evidence/screenshot_1.png", None),
        ("GET", f"/api/v1/scans/{SCAN}/report?format=md", None),
        ("POST", f"/api/v1/scans/{SCAN}/approvals", {"action": "github_issue", "approved": True}),
        ("GET", f"/api/v1/scans/{SCAN}/audit", None),
    ],
)
def test_every_contract_route_exists_and_is_not_implemented(
    method: str, path: str, body: dict[str, object] | None
) -> None:
    response = client.request(method, path, json=body)
    assert response.status_code == 501
    _assert_error_shape(response.json(), "not_implemented")


@pytest.mark.parametrize(
    "body",
    [
        {"target_url": "https://example.com", "profile": "deep"},
        {"profile": "smoke"},
        {"target_url": "https://example.com", "profile": "smoke", "extra": 1},
    ],
)
def test_create_scan_rejects_bad_body_with_error_shape(body: dict[str, object]) -> None:
    response = client.post("/api/v1/scans", json=body)
    assert response.status_code == 422
    _assert_error_shape(response.json(), "validation_error")


def test_approval_rejects_unknown_action() -> None:
    response = client.post(
        f"/api/v1/scans/{SCAN}/approvals", json={"action": "deploy", "approved": True}
    )
    assert response.status_code == 422
    _assert_error_shape(response.json(), "validation_error")


def test_unknown_route_uses_error_shape() -> None:
    response = client.get("/api/v1/nope")
    assert response.status_code == 404
    _assert_error_shape(response.json(), "http_404")


def test_bad_report_format_rejected() -> None:
    response = client.get(f"/api/v1/scans/{SCAN}/report?format=docx")
    assert response.status_code == 422
