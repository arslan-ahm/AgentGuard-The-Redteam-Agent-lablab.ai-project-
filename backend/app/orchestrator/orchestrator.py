"""Scan orchestrator: the state machine of brief 5.2. Owner: Sohaib.

``queued -> planning -> running -> verifying -> awaiting_approval | completed``, with
``failed`` for unexpected errors and ``blocked`` when no task could run because the policy
refused every one. Rules (brief 6.2):

- every state change writes an audit event;
- job handling is idempotent: a scan is *claimed* with one atomic ``UPDATE ... WHERE
  status = 'queued'``, so a duplicate job, a retry or a second worker does nothing;
- the Planner and Sandbox are only used through ``app.interfaces`` protocols;
- plans are validated again here (whitelisted check ids, task cap, unique task ids), because
  the orchestrator must not run whatever a planner returns.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from agentguard_contracts import (
    ALLOWED_CHECK_IDS,
    MAX_TASKS_PER_PROFILE,
    AuditActor,
    AuditDecision,
    AuditEvent,
    Finding,
    PlanTask,
    SandboxResult,
    SandboxResultStatus,
    SandboxTaskInput,
    ScanStatus,
    TestPlan,
)
from sqlalchemy import select, update

from app.db.models import FindingRow, Scan, ScanTask
from app.orchestrator.scoring import compute_score, recommend

if TYPE_CHECKING:
    from app.orchestrator.services import Services

log = logging.getLogger(__name__)

CONTAINMENT_TASK = PlanTask(
    task_id="t-containment",
    check_id="security.exposed_endpoints",
    description="Containment demo: try to reach the cloud metadata service",
    params={"containment_demo": True},
    timeout_s=30,
)
"""Appended to the plan of a scan created with the containment-demo flag (Arslan's trigger)."""

TERMINAL = frozenset(
    {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.BLOCKED, ScanStatus.AWAITING_APPROVAL}
)
"""States after which the orchestrator is done and the SSE stream closes."""


STALE_AFTER_S = 3600.0
"""An active scan with no update for this long belongs to a dead worker (job timeout is 1800s)."""


class PlanRejectedError(ValueError):
    """The planner returned a plan the orchestrator refuses to run."""


def validate_plan(plan: TestPlan, scan: Scan) -> None:
    """Defence in depth on top of the planner's own validation (brief 6.3)."""
    cap = MAX_TASKS_PER_PROFILE[scan.profile]
    if not plan.tasks:
        raise PlanRejectedError("plan has no tasks")
    if len(plan.tasks) > cap:
        raise PlanRejectedError(
            f"plan has {len(plan.tasks)} tasks; {scan.profile.value} allows {cap}"
        )
    ids = [t.task_id for t in plan.tasks]
    if len(set(ids)) != len(ids):
        raise PlanRejectedError("duplicate task ids in plan")
    for task in plan.tasks:
        if task.check_id not in ALLOWED_CHECK_IDS:
            raise PlanRejectedError(f"check id not allowed: {task.check_id}")
        if task.params.get("containment_demo") is True:
            raise PlanRejectedError("containment demo tasks are added by the orchestrator only")


def evidence_name(task_id: str, filename: str) -> str:
    """Evidence names are unique per scan: ``<task_id>__<filename>`` (every task writes its own
    ``screenshot_1.png``). ``GET /scans/{id}/evidence/{filename}`` splits on the first ``__``."""
    return f"{task_id}__{filename}"


class Orchestrator:
    """Runs one scan from ``queued`` to a final state."""

    def __init__(self, services: Services) -> None:
        self.s = services

    # -- audit + state ---------------------------------------------------------------------

    async def _audit(
        self,
        scan_id: UUID,
        action: str,
        target: str,
        reason: str,
        *,
        allowed: bool = True,
        task_id: str | None = None,
        actor: AuditActor = AuditActor.API,
    ) -> None:
        await self.s.audit.append(
            AuditEvent(
                ts=datetime.now(UTC),
                scan_id=scan_id,
                task_id=task_id,
                actor=actor,
                action=action,
                target=target,
                decision=AuditDecision.ALLOWED if allowed else AuditDecision.BLOCKED,
                reason=reason,
            )
        )

    async def _set_status(
        self, scan_id: UUID, status: ScanStatus, reason: str, **fields: object
    ) -> None:
        with self.s.session_factory() as db:
            db.execute(update(Scan).where(Scan.id == scan_id).values(status=status, **fields))
            db.commit()
        await self._audit(scan_id, "scan.status", status.value, reason)

    def _claim(self, scan_id: UUID) -> bool:
        """Atomically move ``queued -> planning``. False if someone else already did."""
        with self.s.session_factory() as db:
            result = db.execute(
                update(Scan)
                .where(Scan.id == scan_id, Scan.status == ScanStatus.QUEUED)
                .values(status=ScanStatus.PLANNING)
            )
            db.commit()
            return bool(result.rowcount)  # type: ignore[attr-defined]

    async def fail_stale_scans(self, older_than_s: float = STALE_AFTER_S) -> list[UUID]:
        """Fail scans a dead worker left in an active state (``planning``/``running``/
        ``verifying``) with no update for ``older_than_s``. A claimed scan is never re-queued, so
        without this a crash leaves it stuck forever. Returns the ids that were failed."""
        cutoff = datetime.now(UTC) - timedelta(seconds=older_than_s)
        active = (ScanStatus.PLANNING, ScanStatus.RUNNING, ScanStatus.VERIFYING)
        reason = f"worker stopped responding (no progress for {int(older_than_s)}s)"
        failed: list[UUID] = []
        with self.s.session_factory() as db:
            ids = list(
                db.scalars(select(Scan.id).where(Scan.status.in_(active), Scan.updated_at < cutoff))
            )
            for scan_id in ids:
                changed = db.execute(
                    update(Scan)
                    .where(Scan.id == scan_id, Scan.status.in_(active), Scan.updated_at < cutoff)
                    .values(status=ScanStatus.FAILED, error=reason)
                )
                if changed.rowcount:  # type: ignore[attr-defined]
                    failed.append(scan_id)
            db.commit()
        for scan_id in failed:
            await self._audit(scan_id, "scan.status", ScanStatus.FAILED.value, reason)
        return failed

    # -- the run ---------------------------------------------------------------------------

    async def run_scan(self, scan_id: UUID) -> None:
        """Entry point for the queue. Never raises: failures end the scan as ``failed``."""
        if not await asyncio.to_thread(self._claim, scan_id):
            log.info("scan %s already claimed or not queued; skipping", scan_id)
            return
        await self._audit(scan_id, "scan.status", ScanStatus.PLANNING.value, "claimed by worker")
        try:
            await self._run(scan_id)
        except Exception as exc:  # last line of defence: a scan must always reach a final state
            log.exception("scan %s failed", scan_id)
            reason = f"{type(exc).__name__}: {str(exc)[:300]}"
            await self._set_status(scan_id, ScanStatus.FAILED, reason, error=reason)

    async def _run(self, scan_id: UUID) -> None:
        with self.s.session_factory() as db:
            scan = db.get(Scan, scan_id)
            if scan is None:
                raise LookupError("scan vanished")
            db.expunge(scan)

        plan = await self.s.planner.plan(scan.target_url, scan.profile)
        plan = plan.model_copy(update={"scan_id": scan_id, "target_url": scan.target_url})
        validate_plan(plan, scan)
        tasks = list(plan.tasks)
        if scan.containment_demo:
            tasks.append(CONTAINMENT_TASK)
            await self._audit(scan_id, "containment_demo.armed", CONTAINMENT_TASK.task_id, "flag")

        with self.s.session_factory() as db:
            db.add_all(
                ScanTask(
                    scan_id=scan_id,
                    task_id=t.task_id,
                    position=i,
                    check_id=t.check_id,
                    description=t.description,
                    params=t.params,
                    timeout_s=t.timeout_s,
                )
                for i, t in enumerate(tasks)
            )
            db.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(plan=plan.model_dump(mode="json"), tasks_total=len(tasks))
            )
            db.commit()
        await self._audit(scan_id, "plan.created", f"{len(tasks)} tasks", scan.profile.value)
        await self._set_status(scan_id, ScanStatus.RUNNING, "plan accepted")

        findings: list[Finding] = []
        statuses: list[SandboxResultStatus] = []
        for done, task in enumerate(tasks, start=1):
            result = await self._run_task(scan, task, done)
            statuses.append(result.status)
            findings.extend(await self._store_findings(scan, task, result))

        await self._set_status(scan_id, ScanStatus.VERIFYING, "all tasks finished")
        confirmed, review = await self.s.verifier.verify(findings)
        with self.s.session_factory() as db:
            for f in review:
                row = db.get(FindingRow, f.id)
                if row is not None:
                    row.needs_review = True
            db.commit()
        score = compute_score(f.severity for f in confirmed)
        summary = await self.s.planner.summarize(confirmed)

        ran = [s for s in statuses if s in (SandboxResultStatus.PASSED, SandboxResultStatus.FAILED)]
        errored = sum(1 for s in statuses if s is SandboxResultStatus.ERROR)
        if statuses and all(s is SandboxResultStatus.BLOCKED for s in statuses):
            final, why = ScanStatus.BLOCKED, "the policy blocked every task"
        elif not ran:
            # Nothing actually ran (Docker down, every task timed out...). A score here would
            # read as "no problems found", so there is none.
            reason = f"no task completed ({errored} errored, {len(statuses) - errored} blocked)"
            await self._set_status(scan_id, ScanStatus.FAILED, reason, error=reason, summary=reason)
            return
        elif findings:
            final, why = ScanStatus.AWAITING_APPROVAL, "findings need a human decision"
        else:
            final, why = ScanStatus.COMPLETED, "no findings"
        if errored:
            summary = (
                f"Incomplete: {errored} of {len(statuses)} tasks errored, so some checks "
                f"did not run. {summary}"
            )
        await self._set_status(
            scan_id,
            final,
            why,
            score=score,
            recommendation=recommend(score).value,
            summary=summary[:4000],
        )

    async def _run_task(self, scan: Scan, task: PlanTask, done: int) -> SandboxResult:
        started = datetime.now(UTC)
        await self._audit(
            scan.id, "task.started", task.check_id, "dispatched to sandbox", task_id=task.task_id
        )
        try:
            result = await self.s.sandbox.run(
                SandboxTaskInput(scan_id=scan.id, target_url=scan.target_url, task=task)
            )
        except Exception as exc:  # one broken task must not abort the whole scan
            log.exception("task %s of scan %s crashed", task.task_id, scan.id)
            result = SandboxResult(
                task_id=task.task_id,
                status=SandboxResultStatus.ERROR,
                findings=[],
                duration_ms=0,
                policy_events=[],
            )
            await self._audit(
                scan.id,
                "task.error",
                task.check_id,
                f"{type(exc).__name__}",
                allowed=False,
                task_id=task.task_id,
            )
        with self.s.session_factory() as db:
            db.execute(
                update(ScanTask)
                .where(ScanTask.scan_id == scan.id, ScanTask.task_id == task.task_id)
                .values(
                    status=result.status,
                    duration_ms=result.duration_ms,
                    policy_events=result.policy_events,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                )
            )
            db.execute(update(Scan).where(Scan.id == scan.id).values(tasks_done=done))
            db.commit()
        await self._audit(
            scan.id,
            "task.finished",
            task.check_id,
            result.status.value,
            allowed=result.status is not SandboxResultStatus.BLOCKED,
            task_id=task.task_id,
        )
        return result

    async def _store_findings(
        self, scan: Scan, task: PlanTask, result: SandboxResult
    ) -> list[Finding]:
        stored: list[Finding] = []
        with self.s.session_factory() as db:
            for draft in result.findings:
                data = draft.model_dump()
                data["evidence"] = [evidence_name(task.task_id, e) for e in draft.evidence]
                row = FindingRow(id=uuid4(), scan_id=scan.id, task_id=task.task_id, **data)
                db.add(row)
                stored.append(Finding(id=row.id, scan_id=scan.id, **data))
            db.commit()
        return stored
