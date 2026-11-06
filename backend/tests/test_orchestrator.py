"""Orchestrator state machine with fake planner and sandbox (Sohaib: orchestration)."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from agentguard_contracts import (
    PlanTask,
    SandboxResult,
    SandboxResultStatus,
    SandboxTaskInput,
    ScanProfile,
    ScanStatus,
    TestPlan,
)
from sqlalchemy import select

from app.db.models import FindingRow, Scan, ScanTask
from app.orchestrator.fakes import FakePlanner
from app.orchestrator.orchestrator import Orchestrator, PlanRejectedError, validate_plan
from app.orchestrator.scoring import compute_score, recommend
from app.orchestrator.services import Services
from tests.conftest import make_services


def _new_scan(
    services: Services, profile: ScanProfile = ScanProfile.FULL, *, demo: bool = False
) -> UUID:
    scan_id = uuid4()
    with services.session_factory() as db:
        db.add(
            Scan(
                id=scan_id,
                owner="alice@example.com",
                target_url="https://shop.example.com",
                profile=profile,
                containment_demo=demo,
            )
        )
        db.commit()
    return scan_id


def _scan(services: Services, scan_id: UUID) -> Scan:
    with services.session_factory() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        return scan


async def _audit_actions(services: Services, scan_id: UUID) -> list[tuple[str, str]]:
    return [(e.action, e.target) for _, e in services.audit_store.events_since(scan_id)]


async def test_full_scan_reaches_awaiting_approval_with_score(services: Services) -> None:
    scan_id = _new_scan(services)
    await Orchestrator(services).run_scan(scan_id)

    scan = _scan(services, scan_id)
    assert scan.status is ScanStatus.AWAITING_APPROVAL
    assert scan.tasks_total == scan.tasks_done == 8
    # fake sandbox: 1 medium + 2 high + 1 low -> 100 - 5 - 24 - 1
    assert scan.score == 70
    assert scan.recommendation == "Fix high-priority issues before release"
    assert scan.summary

    with services.session_factory() as db:
        assert len(db.scalars(select(FindingRow)).all()) == 4
        assert all(
            t.status is not None for t in db.scalars(select(ScanTask).order_by(ScanTask.position))
        )


async def test_every_state_change_is_audited_in_order(services: Services) -> None:
    scan_id = _new_scan(services, ScanProfile.SMOKE)
    await Orchestrator(services).run_scan(scan_id)

    statuses = [t for a, t in await _audit_actions(services, scan_id) if a == "scan.status"]
    assert statuses == ["planning", "running", "verifying", "awaiting_approval"]


async def test_audit_chain_stays_valid(services: Services) -> None:
    await Orchestrator(services).run_scan(_new_scan(services, ScanProfile.QA))
    ok, broken = await services.audit.verify()
    assert ok and broken is None


async def test_clean_scan_completes(services: Services) -> None:
    class CleanPlanner(FakePlanner):
        async def plan(self, target_url: str, profile: ScanProfile) -> TestPlan:
            plan = await super().plan(target_url, profile)
            return plan.model_copy(update={"tasks": [plan.tasks[0]]})  # qa.pages_load: no finding

    services.planner = CleanPlanner()
    scan_id = _new_scan(services, ScanProfile.SMOKE)
    await Orchestrator(services).run_scan(scan_id)
    scan = _scan(services, scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert scan.score == 100 and scan.recommendation == "Safe to ship with monitoring"


async def test_second_run_of_same_scan_is_a_noop(services: Services) -> None:
    scan_id = _new_scan(services, ScanProfile.SMOKE)
    orchestrator = Orchestrator(services)
    await orchestrator.run_scan(scan_id)
    before = await _audit_actions(services, scan_id)
    await orchestrator.run_scan(scan_id)  # duplicate job
    assert await _audit_actions(services, scan_id) == before
    with services.session_factory() as db:
        assert len(db.scalars(select(ScanTask)).all()) == 3  # not planned twice


async def test_concurrent_runs_execute_the_scan_once(services: Services) -> None:
    import asyncio

    scan_id = _new_scan(services, ScanProfile.SMOKE)
    orchestrator = Orchestrator(services)
    await asyncio.gather(*(orchestrator.run_scan(scan_id) for _ in range(5)))
    with services.session_factory() as db:
        assert len(db.scalars(select(ScanTask)).all()) == 3


async def test_containment_demo_task_is_appended_and_blocked(services: Services) -> None:
    scan_id = _new_scan(services, ScanProfile.SMOKE, demo=True)
    await Orchestrator(services).run_scan(scan_id)

    with services.session_factory() as db:
        demo = db.scalars(select(ScanTask).where(ScanTask.task_id == "t-containment")).one()
    assert demo.check_id == "security.exposed_endpoints"
    assert demo.params == {"containment_demo": True}
    assert demo.status is SandboxResultStatus.BLOCKED
    events = services.audit_store.events_since(scan_id)
    assert any(e.actor.value == "policy" and e.decision.value == "blocked" for _, e in events)
    assert any(e.action == "sandbox_destroyed" and e.task_id == "t-containment" for _, e in events)
    # the other tasks still ran: one blocked task does not block the scan
    assert _scan(services, scan_id).status is ScanStatus.AWAITING_APPROVAL


async def test_without_flag_there_is_no_containment_task(services: Services) -> None:
    scan_id = _new_scan(services, ScanProfile.SMOKE)
    await Orchestrator(services).run_scan(scan_id)
    with services.session_factory() as db:
        assert (
            db.scalars(select(ScanTask).where(ScanTask.task_id == "t-containment")).first() is None
        )


async def test_scan_is_blocked_when_every_task_is_blocked(services: Services) -> None:
    class BlockEverything:
        async def run(self, task: SandboxTaskInput) -> SandboxResult:
            return SandboxResult(
                task_id=task.task.task_id,
                status=SandboxResultStatus.BLOCKED,
                findings=[],
                duration_ms=1,
                policy_events=[],
            )

    services.sandbox = BlockEverything()
    scan_id = _new_scan(services, ScanProfile.SMOKE)
    await Orchestrator(services).run_scan(scan_id)
    assert _scan(services, scan_id).status is ScanStatus.BLOCKED


async def test_crashing_task_becomes_error_and_scan_continues(services: Services) -> None:
    class Flaky:
        def __init__(self) -> None:
            self.calls = 0

        async def run(self, task: SandboxTaskInput) -> SandboxResult:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("docker exploded")
            return SandboxResult(
                task_id=task.task.task_id,
                status=SandboxResultStatus.PASSED,
                findings=[],
                duration_ms=1,
                policy_events=[],
            )

    services.sandbox = Flaky()
    scan_id = _new_scan(services, ScanProfile.SMOKE)
    await Orchestrator(services).run_scan(scan_id)
    with services.session_factory() as db:
        statuses = [t.status for t in db.scalars(select(ScanTask).order_by(ScanTask.position))]
    assert statuses == [
        SandboxResultStatus.ERROR,
        SandboxResultStatus.PASSED,
        SandboxResultStatus.PASSED,
    ]
    assert _scan(services, scan_id).status is ScanStatus.COMPLETED


async def test_planner_failure_marks_scan_failed(services: Services) -> None:
    class Broken(FakePlanner):
        async def plan(self, target_url: str, profile: ScanProfile) -> TestPlan:
            raise TimeoutError("inference timed out")

    services.planner = Broken()
    scan_id = _new_scan(services)
    await Orchestrator(services).run_scan(scan_id)  # must not raise
    scan = _scan(services, scan_id)
    assert scan.status is ScanStatus.FAILED
    assert "TimeoutError" in (scan.error or "")
    assert ("scan.status", "failed") in await _audit_actions(services, scan_id)


@pytest.mark.parametrize(
    ("tasks", "message"),
    [
        ([], "no tasks"),
        (
            [PlanTask(task_id="a", check_id="evil.rm_rf", description="", timeout_s=5)],
            "not allowed",
        ),
        (
            [
                PlanTask(task_id="a", check_id="qa.forms", description="", timeout_s=5),
                PlanTask(task_id="a", check_id="qa.search", description="", timeout_s=5),
            ],
            "duplicate",
        ),
        (
            [
                PlanTask(
                    task_id="a",
                    check_id="security.exposed_endpoints",
                    description="",
                    params={"containment_demo": True},
                    timeout_s=5,
                )
            ],
            "orchestrator only",
        ),
        (
            [
                PlanTask(task_id=f"t{i}", check_id="qa.forms", description="", timeout_s=5)
                for i in range(6)
            ],
            "allows 5",
        ),
    ],
)
def test_validate_plan_rejects_unsafe_plans(
    services: Services, tasks: list[PlanTask], message: str
) -> None:
    scan = Scan(target_url="https://x.example", profile=ScanProfile.SMOKE)
    plan = TestPlan(scan_id=uuid4(), target_url=scan.target_url, profile=scan.profile, tasks=tasks)
    with pytest.raises(PlanRejectedError, match=message):
        validate_plan(plan, scan)


async def test_planner_returning_bad_check_id_fails_the_scan(services: Services) -> None:
    class Evil(FakePlanner):
        async def plan(self, target_url: str, profile: ScanProfile) -> TestPlan:
            bad = PlanTask(task_id="x", check_id="qa.not_real", description="", timeout_s=5)
            return TestPlan(scan_id=uuid4(), target_url=target_url, profile=profile, tasks=[bad])

    services.planner = Evil()
    scan_id = _new_scan(services)
    await Orchestrator(services).run_scan(scan_id)
    scan = _scan(services, scan_id)
    assert scan.status is ScanStatus.FAILED and "not allowed" in (scan.error or "")


async def test_low_confidence_findings_go_to_review_and_not_to_score(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from agentguard_contracts import FindingCategory, FindingDraft, Severity

    class Unsure:
        async def run(self, task: SandboxTaskInput) -> SandboxResult:
            draft = FindingDraft(
                title="maybe",
                category=FindingCategory.SECURITY,
                severity=Severity.CRITICAL,
                confidence=0.3,
                url=task.target_url,
                evidence=["shot.png"],
                reproduction=["x"],
                impact="i",
                recommended_fix="f",
                check_id=task.task.check_id,
            )
            return SandboxResult(
                task_id=task.task.task_id,
                status=SandboxResultStatus.FAILED,
                findings=[draft],
                duration_ms=1,
                policy_events=[],
            )

    services = make_services(tmp_path, sandbox=Unsure())
    scan_id = _new_scan(services, ScanProfile.SMOKE)
    await Orchestrator(services).run_scan(scan_id)
    scan = _scan(services, scan_id)
    assert scan.score == 100  # the unsure critical findings are not counted
    with services.session_factory() as db:
        rows = db.scalars(select(FindingRow)).all()
        assert rows and all(r.needs_review for r in rows)
        assert rows[0].evidence == [f"{rows[0].task_id}__shot.png"]  # evidence names are unique


@pytest.mark.parametrize(
    ("severities", "score", "text"),
    [
        ([], 100, "Safe to ship with monitoring"),
        (["low"] * 3, 97, "Safe to ship with monitoring"),
        (["high", "medium", "medium", "low"], 77, "Fix high-priority issues before release"),
        (["critical"] * 2, 50, "Fix high-priority issues before release"),
        (["critical"] * 2 + ["low"], 49, "Block release"),
        (["critical"] * 5, 0, "Block release"),
    ],
)
def test_score_and_recommendation_follow_brief_5_10(
    severities: list[str], score: int, text: str
) -> None:
    from agentguard_contracts import Severity

    value = compute_score(Severity(s) for s in severities)
    assert value == score
    assert recommend(value).value == text
