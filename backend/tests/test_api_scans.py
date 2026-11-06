"""Scan endpoints end to end with fakes: create, poll, findings, report, audit, SSE, approvals,
evidence and isolation between users (Sohaib: API)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import Scan
from app.orchestrator.services import Services
from app.policy.rate_limit import ScanRateLimiter
from tests.conftest import login

BODY = {"target_url": "https://shop.example.com", "profile": "smoke"}
FINAL = {"awaiting_approval", "completed", "failed", "blocked"}


def _wait_final(client: TestClient, scan_id: str, headers: dict[str, str]) -> dict[str, object]:
    for _ in range(100):
        scan = client.get(f"/api/v1/scans/{scan_id}", headers=headers).json()
        if scan["status"] in FINAL:
            return scan  # type: ignore[no-any-return]
        time.sleep(0.05)
    raise AssertionError(f"scan never finished: {scan}")


def _create(client: TestClient, auth: dict[str, str], **extra: object) -> str:
    response = client.post("/api/v1/scans", json={**BODY, **extra}, headers=auth)
    assert response.status_code == 202, response.text
    assert response.json()["status"] == "queued"
    return str(response.json()["id"])


def test_create_then_poll_to_final_state(client: TestClient, auth: dict[str, str]) -> None:
    scan_id = _create(client, auth)
    scan = _wait_final(client, scan_id, auth)
    assert scan["status"] == "awaiting_approval"
    assert scan["progress"] == {"tasks_total": 3, "tasks_done": 3}
    assert scan["score"] == 94 and scan["recommendation"] == "Safe to ship with monitoring"
    assert scan["target_url"] == BODY["target_url"]


def test_findings_follow_the_5_4_contract(client: TestClient, auth: dict[str, str]) -> None:
    scan_id = _create(client, auth)
    _wait_final(client, scan_id, auth)
    findings = client.get(f"/api/v1/scans/{scan_id}/findings", headers=auth).json()
    assert {f["check_id"] for f in findings} == {"security.headers", "qa.console_network_errors"}
    for f in findings:
        assert set(f) == {
            "id", "scan_id", "title", "category", "severity", "confidence", "url", "evidence",
            "reproduction", "impact", "recommended_fix", "check_id", "verified",
        }  # fmt: skip
        assert f["scan_id"] == scan_id


def test_list_returns_only_my_scans_newest_first(client: TestClient, auth: dict[str, str]) -> None:
    first = _create(client, auth)
    time.sleep(0.01)
    second = _create(client, auth)
    bob = login(client, "bob@example.com")
    _create(client, bob)
    mine = client.get("/api/v1/scans", headers=auth).json()
    assert [s["id"] for s in mine] == [second, first]
    assert len(client.get("/api/v1/scans", headers=bob).json()) == 1


def test_other_users_get_404_not_403(client: TestClient, auth: dict[str, str]) -> None:
    scan_id = _create(client, auth)
    bob = login(client, "bob@example.com")
    for suffix in ("", "/findings", "/audit", "/report", "/events", "/evidence/t1__a.png"):
        response = client.get(f"/api/v1/scans/{scan_id}{suffix}", headers=bob)
        assert response.status_code == 404, suffix
    approval = client.post(
        f"/api/v1/scans/{scan_id}/approvals",
        json={"action": "send_report", "approved": True},
        headers=bob,
    )
    assert approval.status_code == 404


def test_blocked_target_is_refused_recorded_and_audited(
    client: TestClient, auth: dict[str, str], services: Services
) -> None:
    response = client.post(
        "/api/v1/scans", json={**BODY, "target_url": "http://169.254.169.254/"}, headers=auth
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "target_blocked"
    scans = client.get("/api/v1/scans", headers=auth).json()
    assert [s["status"] for s in scans] == ["blocked"]
    audit = client.get(f"/api/v1/scans/{scans[0]['id']}/audit", headers=auth).json()
    assert audit[0]["actor"] == "policy" and audit[0]["decision"] == "blocked"
    with services.session_factory() as db:  # nothing was queued: no tasks were planned
        assert db.scalars(select(Scan)).one().tasks_done == 0


def test_rate_limit_returns_429_with_retry_after(tmp_path: Path) -> None:
    from app.main import create_app
    from tests.conftest import make_services

    services = make_services(tmp_path, rate_limiter=ScanRateLimiter(user_limit=1))
    with TestClient(create_app(services)) as client:
        auth = login(client)
        assert client.post("/api/v1/scans", json=BODY, headers=auth).status_code == 202
        second = client.post("/api/v1/scans", json=BODY, headers=auth)
        assert second.status_code == 429
        assert second.json()["error"]["code"] == "rate_limited"
        assert int(second.headers["retry-after"]) > 0


def test_audit_endpoint_lists_the_scan_trail(client: TestClient, auth: dict[str, str]) -> None:
    scan_id = _create(client, auth)
    _wait_final(client, scan_id, auth)
    audit = client.get(f"/api/v1/scans/{scan_id}/audit", headers=auth).json()
    assert [e["target"] for e in audit if e["action"] == "scan.status"] == [
        "queued", "planning", "running", "verifying", "awaiting_approval",
    ]  # fmt: skip
    assert {"sandbox_launched", "sandbox_destroyed", "task.finished"} <= {
        e["action"] for e in audit
    }
    assert all(
        set(e) == {"ts", "scan_id", "task_id", "actor", "action", "target", "decision", "reason"}
        for e in audit
    )


def test_containment_header_arms_the_demo_task(client: TestClient, auth: dict[str, str]) -> None:
    response = client.post(
        "/api/v1/scans", json=BODY, headers={**auth, "X-AgentGuard-Demo": "containment"}
    )
    scan_id = response.json()["id"]
    scan = _wait_final(client, scan_id, auth)
    assert scan["progress"] == {"tasks_total": 4, "tasks_done": 4}
    audit = client.get(f"/api/v1/scans/{scan_id}/audit", headers=auth).json()
    assert any(e["actor"] == "policy" and e["decision"] == "blocked" for e in audit)


def test_events_stream_replays_audit_and_progress_then_closes(
    client: TestClient, auth: dict[str, str]
) -> None:
    scan_id = _create(client, auth)
    _wait_final(client, scan_id, auth)
    with client.stream("GET", f"/api/v1/scans/{scan_id}/events", headers=auth) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        text = "".join(response.iter_text())
    kinds = [line.split(": ", 1)[1] for line in text.splitlines() if line.startswith("event: ")]
    assert "audit" in kinds and kinds[-1] == "progress"
    audit_lines = [
        line for line in text.splitlines() if line.startswith("data: {") and '"actor"' in line
    ]
    assert json.loads(audit_lines[0][6:])["target"] == "queued"
    ids = [int(line[4:]) for line in text.splitlines() if line.startswith("id: ")]
    assert ids == sorted(ids)

    resume_headers = {**auth, "Last-Event-ID": str(ids[-1])}
    with client.stream("GET", f"/api/v1/scans/{scan_id}/events", headers=resume_headers) as again:
        resumed = "".join(again.iter_text())
    assert "event: audit" not in resumed  # nothing newer than the last seen id


def test_report_json_and_markdown_and_pdf(client: TestClient, auth: dict[str, str]) -> None:
    scan_id = _create(client, auth)
    _wait_final(client, scan_id, auth)
    as_json = client.get(f"/api/v1/scans/{scan_id}/report", headers=auth)
    assert as_json.status_code == 200
    assert as_json.json()["scan"]["id"] == scan_id and len(as_json.json()["findings"]) == 2
    md = client.get(f"/api/v1/scans/{scan_id}/report?format=md", headers=auth)
    assert md.headers["content-type"].startswith("text/markdown")
    assert "# AgentGuard report: https://shop.example.com" in md.text
    assert "[MEDIUM] Missing security headers" in md.text
    pdf = client.get(f"/api/v1/scans/{scan_id}/report?format=pdf", headers=auth)
    assert pdf.status_code == 501 and pdf.json()["error"]["code"] == "not_implemented"


def test_approval_flow(client: TestClient, auth: dict[str, str]) -> None:
    scan_id = _create(client, auth)
    early = client.post(
        f"/api/v1/scans/{scan_id}/approvals",
        json={"action": "github_issue", "approved": True},
        headers=auth,
    )
    assert early.status_code in (200, 409)  # racing the worker: both are legitimate
    _wait_final(client, scan_id, auth)
    declined = client.post(
        f"/api/v1/scans/{scan_id}/approvals",
        json={"action": "send_report", "approved": False},
        headers=auth,
    )
    assert declined.status_code == 200
    assert (
        declined.json()["scan_status"] == "awaiting_approval"
        and declined.json()["executed"] is False
    )
    approved = client.post(
        f"/api/v1/scans/{scan_id}/approvals",
        json={"action": "github_issue", "approved": True},
        headers=auth,
    )
    if early.status_code == 409:
        assert approved.status_code == 200 and approved.json()["scan_status"] == "completed"
    again = client.post(
        f"/api/v1/scans/{scan_id}/approvals",
        json={"action": "send_report", "approved": True},
        headers=auth,
    )
    assert again.status_code == 409 and again.json()["error"]["code"] == "already_decided"
    audit = client.get(f"/api/v1/scans/{scan_id}/audit", headers=auth).json()
    actions = {e["action"]: e["decision"] for e in audit}
    assert actions["approval.send_report"] == "blocked"  # the declined one


@pytest.mark.parametrize(
    "name",
    ["t1__../../../etc/passwd", "..%2f..%2fsecret", "t1__.hidden.png", "no-separator.png",
     "t1__a/b.png", "t1__a.exe", "t9__ghost.png", "x" * 300 + ".png"],
)  # fmt: skip
def test_evidence_rejects_traversal_and_unknown_files(
    client: TestClient, auth: dict[str, str], name: str
) -> None:
    scan_id = _create(client, auth)
    _wait_final(client, scan_id, auth)
    response = client.get(f"/api/v1/scans/{scan_id}/evidence/{name}", headers=auth)
    assert response.status_code == 404


def test_evidence_serves_a_real_file_and_never_a_symlink(
    client: TestClient, auth: dict[str, str], services: Services, tmp_path: Path
) -> None:
    scan_id = _create(client, auth)
    _wait_final(client, scan_id, auth)
    out = services.evidence_root / scan_id / "t1" / "out"
    (out / "screenshots").mkdir(parents=True)
    (out / "screenshots" / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (out / "network_summary.json").write_text("{}")
    secret = tmp_path / "secret.png"
    secret.write_bytes(b"top secret")
    try:
        (out / "screenshots" / "link.png").symlink_to(secret)
        can_link = True
    except OSError:  # symlinks need privileges on Windows
        can_link = False

    ok = client.get(f"/api/v1/scans/{scan_id}/evidence/t1__shot.png", headers=auth)
    assert ok.status_code == 200 and ok.headers["content-type"] == "image/png"
    assert ok.headers["x-content-type-options"] == "nosniff"
    js = client.get(f"/api/v1/scans/{scan_id}/evidence/t1__network_summary.json", headers=auth)
    assert js.status_code == 200 and js.headers["content-type"] == "application/json"
    if can_link:
        link = client.get(f"/api/v1/scans/{scan_id}/evidence/t1__link.png", headers=auth)
        assert link.status_code == 404
