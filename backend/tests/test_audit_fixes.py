"""Regression tests for the bugs found in the task audit (each one failed before its fix)."""

from __future__ import annotations

import importlib
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agentguard_contracts import (
    SandboxResult,
    SandboxResultStatus,
    SandboxTaskInput,
    ScanProfile,
    ScanStatus,
)
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.db.models import Scan
from app.main import create_app
from app.orchestrator.orchestrator import Orchestrator
from app.orchestrator.services import Services
from tests.conftest import PASSWORD, login
from tests.test_orchestrator import _audit_actions, _new_scan, _scan


class _AlwaysCrash:
    async def run(self, task: SandboxTaskInput) -> SandboxResult:
        raise RuntimeError("docker daemon unreachable")


def _result(task: SandboxTaskInput, status: SandboxResultStatus) -> SandboxResult:
    return SandboxResult(
        task_id=task.task.task_id, status=status, findings=[], duration_ms=1, policy_events=[]
    )


async def test_scan_where_every_task_errors_fails_without_a_score(services: Services) -> None:
    """Used to end 'completed', score 100, 'Safe to ship with monitoring'."""
    services.sandbox = _AlwaysCrash()
    scan_id = _new_scan(services, ScanProfile.SMOKE)
    await Orchestrator(services).run_scan(scan_id)
    scan = _scan(services, scan_id)
    assert scan.status is ScanStatus.FAILED
    assert scan.score is None and scan.recommendation is None
    assert "no task completed" in (scan.error or "")
    assert ("scan.status", "failed") in await _audit_actions(services, scan_id)


async def test_blocked_containment_task_alone_does_not_make_a_failed_scan_look_fine(
    services: Services,
) -> None:
    class CrashExceptDemo:
        async def run(self, task: SandboxTaskInput) -> SandboxResult:
            if task.task.task_id == "t-containment":
                return _result(task, SandboxResultStatus.BLOCKED)
            raise RuntimeError("boom")

    services.sandbox = CrashExceptDemo()
    scan_id = _new_scan(services, ScanProfile.SMOKE, demo=True)
    await Orchestrator(services).run_scan(scan_id)
    scan = _scan(services, scan_id)
    assert scan.status is ScanStatus.FAILED and scan.score is None


async def test_partial_errors_are_stated_in_the_summary(services: Services) -> None:
    class FirstCrashes:
        calls = 0

        async def run(self, task: SandboxTaskInput) -> SandboxResult:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("boom")
            return _result(task, SandboxResultStatus.PASSED)

    services.sandbox = FirstCrashes()
    scan_id = _new_scan(services, ScanProfile.SMOKE)
    await Orchestrator(services).run_scan(scan_id)
    scan = _scan(services, scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert (scan.summary or "").startswith("Incomplete: 1 of 3 tasks errored")


async def test_stale_active_scans_are_failed_and_fresh_ones_left_alone(
    services: Services,
) -> None:
    stale, fresh, queued, done = (_new_scan(services) for _ in range(4))
    old = datetime.now(UTC) - timedelta(hours=3)
    running = {"status": ScanStatus.RUNNING}
    with services.session_factory() as db:
        db.execute(update(Scan).where(Scan.id == stale).values(**running, updated_at=old))
        db.execute(update(Scan).where(Scan.id == fresh).values(**running))
        db.execute(update(Scan).where(Scan.id == queued).values(updated_at=old))
        db.execute(
            update(Scan).where(Scan.id == done).values(status=ScanStatus.COMPLETED, updated_at=old)
        )
        db.commit()

    orchestrator = Orchestrator(services)
    assert await orchestrator.fail_stale_scans(older_than_s=3600) == [stale]
    assert _scan(services, stale).status is ScanStatus.FAILED
    assert "worker stopped responding" in (_scan(services, stale).error or "")
    assert _scan(services, fresh).status is ScanStatus.RUNNING
    assert _scan(services, queued).status is ScanStatus.QUEUED
    assert _scan(services, done).status is ScanStatus.COMPLETED
    assert ("scan.status", "failed") in await _audit_actions(services, stale)
    assert await orchestrator.fail_stale_scans(older_than_s=3600) == []  # idempotent


def test_queue_name_matches_the_deployed_worker() -> None:
    """The API enqueued on 'scans' while the deployed worker read 'agentguard'."""
    from app.orchestrator.queue import JOB_PATH, QUEUE_NAME

    worker = Path(__file__).resolve().parents[2] / "deploy" / "worker.Dockerfile"
    if not worker.exists():
        pytest.skip("deploy/worker.Dockerfile not present")
    cmd = next(line for line in worker.read_text().splitlines() if line.startswith("CMD"))
    assert f'"{QUEUE_NAME}"' in cmd
    module, _, func = JOB_PATH.rpartition(".")
    assert callable(getattr(importlib.import_module(module), func))


def test_backend_image_migrates_before_serving() -> None:
    """Nothing in deploy created the tables, so the first request would have failed."""
    text = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    cmd = next(line for line in text.splitlines() if line.startswith("CMD"))
    assert cmd.index("alembic upgrade head") < cmd.index("uvicorn")
    assert "&&" in cmd  # uvicorn must not start if the migration fails


def test_a_stranger_cannot_lock_the_owner_out(services: Services) -> None:
    """The lockout was keyed by email only, so anyone could lock anyone out."""
    app = create_app(services)
    with (
        TestClient(app, client=("203.0.113.9", 4000)) as attacker,
        TestClient(app, client=("198.51.100.7", 4000)) as owner,
    ):
        for _ in range(12):
            attacker.post(
                "/api/v1/auth/login", json={"email": "alice@example.com", "password": "bad"}
            )
        slowed = attacker.post(
            "/api/v1/auth/login", json={"email": "alice@example.com", "password": PASSWORD}
        )
        assert slowed.status_code == 429  # the attacker is slowed down...
        ok = owner.post(
            "/api/v1/auth/login", json={"email": "alice@example.com", "password": PASSWORD}
        )
        assert ok.status_code == 200  # ...the real owner is not


def test_one_address_is_capped_across_many_emails(services: Services) -> None:
    with TestClient(create_app(services), client=("203.0.113.9", 4000)) as sprayer:
        for i in range(40):
            sprayer.post(
                "/api/v1/auth/login", json={"email": f"user{i}@example.com", "password": "x"}
            )
        blocked = sprayer.post(
            "/api/v1/auth/login", json={"email": "alice@example.com", "password": PASSWORD}
        )
    assert blocked.status_code == 429


def test_api_without_services_answers_503_not_a_crash() -> None:
    response = TestClient(create_app()).get("/api/v1/scans")  # no lifespan, no services
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "not_ready"


def test_approving_a_scan_audits_the_status_change(client: TestClient) -> None:
    """awaiting_approval -> completed used to leave no scan.status event."""
    auth = login(client)
    body = {"target_url": "https://shop.example.com", "profile": "smoke", "authorized": True}
    scan_id = client.post("/api/v1/scans", json=body, headers=auth).json()["id"]
    for _ in range(100):
        if client.get(f"/api/v1/scans/{scan_id}", headers=auth).json()["status"] == (
            "awaiting_approval"
        ):
            break
        time.sleep(0.05)
    client.post(
        f"/api/v1/scans/{scan_id}/approvals",
        json={"action": "send_report", "approved": True},
        headers=auth,
    )
    audit = client.get(f"/api/v1/scans/{scan_id}/audit", headers=auth).json()
    trail = [e["target"] for e in audit if e["action"] == "scan.status"]
    assert trail[-2:] == ["awaiting_approval", "completed"]
