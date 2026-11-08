"""REST API from brief 5.8. Owner: Sohaib (API + orchestration), reviewer: Arslan.

Every route except ``/auth/login`` needs ``Authorization: Bearer <token>``. Scans belong to the
user who created them; other users get ``404`` (never ``403``, which would confirm the id).
Errors always use the 5.8 shape. Response models the brief does not spell out live in
``app/api/schemas.py`` and are proposed in CR-2.
"""

from __future__ import annotations

import asyncio
import mimetypes
import re
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated, NoReturn
from uuid import UUID, uuid4

from agentguard_contracts import (
    ApprovalAction,
    ApprovalRequest,
    AuditActor,
    AuditDecision,
    AuditEvent,
    Finding,
    ReportFormat,
    ScanCreate,
    ScanCreated,
    ScanStatus,
)
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import (
    DUMMY_HASH,
    TOKEN_TTL_S,
    AuthNotConfiguredError,
    create_token,
    current_user_factory,
    verify_password,
)
from app.api.schemas import (
    ApprovalResult,
    LoginRequest,
    Progress,
    Report,
    ScanDetail,
    TokenResponse,
)
from app.db.models import Approval, FindingRow, Scan, ScanTask, User, utcnow
from app.orchestrator.orchestrator import TERMINAL
from app.orchestrator.services import Services
from app.policy.url_policy import PolicyBlocked

router = APIRouter()

CONTAINMENT_HEADER_VALUE = "containment"
SSE_POLL_S = 0.5
SSE_HEARTBEAT_S = 15.0
SSE_MAX_S = 900.0
_EVIDENCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$")
_TASK_DIR_UNSAFE = re.compile(r"[^a-zA-Z0-9_.-]")  # same rule as the sandbox launcher
_EVIDENCE_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".json": "application/json"}


def get_services(request: Request) -> Services:
    services: Services | None = getattr(request.app.state, "services", None)
    if services is None:
        _error(status.HTTP_503_SERVICE_UNAVAILABLE, "not_ready", "the API is still starting up")
    return services


ServicesDep = Annotated[Services, Depends(get_services)]
current_user = current_user_factory(lambda request: get_services(request).secret_key)
UserDep = Annotated[str, Depends(current_user)]


def _error(code: int, name: str, message: str, headers: dict[str, str] | None = None) -> NoReturn:
    raise HTTPException(
        status_code=code, detail={"code": name, "message": message}, headers=headers
    )


def _scan_or_404(db: Session, scan_id: UUID, user: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.owner != user:
        _error(status.HTTP_404_NOT_FOUND, "scan_not_found", "scan not found")
    return scan


def _detail(scan: Scan) -> ScanDetail:
    return ScanDetail(
        id=scan.id,
        target_url=scan.target_url,
        profile=scan.profile,
        status=scan.status,
        progress=Progress(tasks_total=scan.tasks_total, tasks_done=scan.tasks_done),
        score=scan.score,
        recommendation=scan.recommendation,
        summary=scan.summary,
        error=scan.error,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
    )


def _finding(row: FindingRow) -> Finding:
    return Finding(
        id=row.id,
        scan_id=row.scan_id,
        title=row.title,
        category=row.category,
        severity=row.severity,
        confidence=row.confidence,
        url=row.url,
        evidence=list(row.evidence),
        reproduction=list(row.reproduction),
        impact=row.impact,
        recommended_fix=row.recommended_fix,
        check_id=row.check_id,
        verified=row.verified,
    )


# -- auth ----------------------------------------------------------------------------------


@router.post("/auth/login", tags=["auth"])
async def login(body: LoginRequest, request: Request, services: ServicesDep) -> TokenResponse:
    """Exchange email + password for a bearer token."""
    email = body.email.strip().lower()
    client = request.client.host if request.client else "unknown"
    pair_key = f"{client}|{email}"
    wait = max(
        services.login_limiter.retry_after(pair_key),
        services.login_ip_limiter.retry_after(client),
    )
    if wait:
        _error(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "rate_limited",
            "too many failed logins; try again later",
            {"Retry-After": str(int(wait) + 1)},
        )
    with services.session_factory() as db:
        user = db.scalar(select(User).where(User.email == email))
    stored = user.password_hash if user else DUMMY_HASH  # always hash: no timing oracle
    valid = await asyncio.to_thread(verify_password, body.password, stored)
    if user is None or not valid:
        services.login_limiter.record(pair_key)
        services.login_ip_limiter.record(client)
        _error(status.HTTP_401_UNAUTHORIZED, "invalid_credentials", "invalid email or password")
    try:
        token = create_token(email, services.secret_key)
    except AuthNotConfiguredError as exc:
        _error(status.HTTP_503_SERVICE_UNAVAILABLE, "auth_not_configured", str(exc))
    return TokenResponse(access_token=token, expires_in=TOKEN_TTL_S)


# -- scans ---------------------------------------------------------------------------------


@router.post("/scans", tags=["scans"], status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    body: ScanCreate,
    services: ServicesDep,
    user: UserDep,
    x_agentguard_demo: Annotated[str | None, Header()] = None,
) -> ScanCreated:
    """Create a scan. The URL policy runs first, then the rate limit, then the job is queued.

    ``X-AgentGuard-Demo: containment`` arms the containment demo task for this scan.
    """
    scan_id = uuid4()
    try:
        await services.policy.assert_allowed(body.target_url)
    except PolicyBlocked as exc:
        reason = str(exc.reason)
        with services.session_factory() as db:
            db.add(
                Scan(
                    id=scan_id,
                    owner=user,
                    target_url=body.target_url[:2048],
                    profile=body.profile,
                    status=ScanStatus.BLOCKED,
                    error=reason,
                )
            )
            db.commit()
        await services.audit.append(
            AuditEvent(
                ts=utcnow(),
                scan_id=scan_id,
                actor=AuditActor.POLICY,
                action="scan.create",
                target=body.target_url[:500],
                decision=AuditDecision.BLOCKED,
                reason=f"{reason}; authorization attested by {user}",
            )
        )
        _error(status.HTTP_403_FORBIDDEN, "target_blocked", reason)

    decision = await services.rate_limiter.check(user, body.target_url)
    if not decision.allowed:
        _error(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "rate_limited",
            decision.reason,
            {"Retry-After": str(int(decision.retry_after_s) + 1)},
        )

    with services.session_factory() as db:
        db.add(
            Scan(
                id=scan_id,
                owner=user,
                target_url=body.target_url,
                profile=body.profile,
                credentials_ref=body.credentials_ref,
                containment_demo=(x_agentguard_demo or "").lower() == CONTAINMENT_HEADER_VALUE,
                status=ScanStatus.QUEUED,
            )
        )
        db.commit()
    await services.audit.append(
        AuditEvent(
            ts=utcnow(),
            scan_id=scan_id,
            actor=AuditActor.API,
            action="scan.status",
            target=ScanStatus.QUEUED.value,
            decision=AuditDecision.ALLOWED,
            reason=f"created by {user}; authorization attested",
        )
    )
    if services.queue is None:
        _error(status.HTTP_503_SERVICE_UNAVAILABLE, "queue_unavailable", "no job queue configured")
    services.queue.enqueue_scan(scan_id)
    return ScanCreated(id=scan_id, status=ScanStatus.QUEUED)


@router.get("/scans", tags=["scans"])
async def list_scans(
    services: ServicesDep, user: UserDep, limit: Annotated[int, Query(ge=1, le=200)] = 100
) -> list[ScanDetail]:
    """Your scans, newest first."""
    with services.session_factory() as db:
        rows = db.scalars(
            select(Scan).where(Scan.owner == user).order_by(Scan.created_at.desc()).limit(limit)
        ).all()
        return [_detail(r) for r in rows]


@router.get("/scans/{scan_id}", tags=["scans"])
async def get_scan(scan_id: UUID, services: ServicesDep, user: UserDep) -> ScanDetail:
    """Status, progress, score, recommendation."""
    with services.session_factory() as db:
        return _detail(_scan_or_404(db, scan_id, user))


def _sse(event: str, data: str, event_id: int | None = None) -> str:
    head = f"id: {event_id}\n" if event_id is not None else ""
    return f"{head}event: {event}\ndata: {data}\n\n"


async def _event_stream(
    request: Request, services: Services, scan_id: UUID, user: str, last_seq: int
) -> AsyncIterator[str]:
    deadline = time.monotonic() + SSE_MAX_S
    last_beat = time.monotonic()
    last_progress: str | None = None
    finishing = False
    while time.monotonic() < deadline and not await request.is_disconnected():
        events = await asyncio.to_thread(services.audit_store.events_since, scan_id, last_seq)
        for seq, event in events:
            yield _sse("audit", event.model_dump_json(), seq)
            last_seq = seq
            last_beat = time.monotonic()

        def snapshot() -> tuple[str, str] | None:
            with services.session_factory() as db:
                scan = db.get(Scan, scan_id)
                if scan is None or scan.owner != user:
                    return None
                return scan.status.value, _detail(scan).model_dump_json()

        snap = await asyncio.to_thread(snapshot)
        if snap is None:
            return
        state, progress = snap
        if progress != last_progress:
            yield _sse("progress", progress)
            last_progress = progress
            last_beat = time.monotonic()
        if finishing:
            return  # one extra pass after the final status so its audit event is not missed
        finishing = ScanStatus(state) in TERMINAL
        if time.monotonic() - last_beat > SSE_HEARTBEAT_S:
            yield ": keep-alive\n\n"
            last_beat = time.monotonic()
        await asyncio.sleep(SSE_POLL_S)


@router.get("/scans/{scan_id}/events", tags=["scans"])
async def scan_events(
    scan_id: UUID,
    request: Request,
    services: ServicesDep,
    user: UserDep,
    last_event_id: Annotated[str | None, Header()] = None,
) -> StreamingResponse:
    """SSE stream: ``audit`` events (every state change, policy decision, sandbox start/stop)
    and ``progress`` snapshots. Closes when the scan reaches a final state. Resume with the
    standard ``Last-Event-ID`` header. Send the bearer token in the ``Authorization`` header
    (browser ``EventSource`` cannot: use ``fetch`` streaming)."""
    with services.session_factory() as db:
        _scan_or_404(db, scan_id, user)
    try:
        start = int(last_event_id) if last_event_id is not None else -1
    except ValueError:
        start = -1
    return StreamingResponse(
        _event_stream(request, services, scan_id, user, start),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/scans/{scan_id}/findings", tags=["findings"])
async def list_findings(scan_id: UUID, services: ServicesDep, user: UserDep) -> list[Finding]:
    """Findings that passed verification (low-confidence ones are in the report's review list)."""
    with services.session_factory() as db:
        _scan_or_404(db, scan_id, user)
        rows = db.scalars(
            select(FindingRow).where(
                FindingRow.scan_id == scan_id, FindingRow.needs_review.is_(False)
            )
        ).all()
        return [_finding(r) for r in rows]


def _evidence_path(services: Services, scan_id: UUID, filename: str, db: Session) -> Path | None:
    """Resolve ``<task_id>__<name>`` to a regular file inside that task's ``out/`` directory."""
    if not _EVIDENCE_NAME.fullmatch(filename) or "__" not in filename:
        return None
    task_id, _, name = filename.partition("__")
    if not name or name.startswith("."):
        return None
    known = db.scalar(
        select(ScanTask.pk).where(ScanTask.scan_id == scan_id, ScanTask.task_id == task_id)
    )
    if known is None:
        return None
    out = (
        services.evidence_root / str(scan_id) / _TASK_DIR_UNSAFE.sub("-", task_id) / "out"
    ).resolve()
    for candidate in (out / "screenshots" / name, out / name):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        if candidate.resolve().is_relative_to(out):
            return candidate
    return None


@router.get("/scans/{scan_id}/evidence/{filename}", tags=["findings"])
async def get_evidence(
    scan_id: UUID, filename: str, services: ServicesDep, user: UserDep
) -> FileResponse:
    """One evidence file (``<task_id>__<name>`` as listed in a finding). Rejects traversal,
    symlinks and anything outside the task's ``out/`` folder; only png, jpg and json are served."""
    with services.session_factory() as db:
        _scan_or_404(db, scan_id, user)
        path = _evidence_path(services, scan_id, filename, db)
    suffix = Path(filename).suffix.lower()
    if path is None or suffix not in _EVIDENCE_TYPES:
        _error(status.HTTP_404_NOT_FOUND, "evidence_not_found", "evidence file not found")
    return FileResponse(
        path,
        media_type=_EVIDENCE_TYPES.get(suffix) or mimetypes.guess_type(filename)[0],
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "private, max-age=300"},
    )


def _report_markdown(report: Report) -> str:
    s = report.scan
    lines = [
        f"# AgentGuard report: {s.target_url}",
        "",
        f"- Profile: {s.profile.value}",
        f"- Status: {s.status.value}",
        f"- Score: {s.score if s.score is not None else 'n/a'}",
        f"- Recommendation: {s.recommendation or 'n/a'}",
        "",
        s.summary or "",
        "",
        "## Findings",
    ]
    if not report.findings:
        lines.append("\nNo findings.")
    for f in report.findings:
        lines += [
            "",
            f"### [{f.severity.value.upper()}] {f.title}",
            f"- Check: `{f.check_id}` · confidence {f.confidence:.2f} · {f.url}",
            f"- Impact: {f.impact}",
            f"- Fix: {f.recommended_fix}",
            "- Reproduce:",
            *[f"  {i}. {step}" for i, step in enumerate(f.reproduction, start=1)],
        ]
    if report.needs_review:
        lines += ["", "## Needs manual review (low confidence)"]
        lines += [f"- {f.title} ({f.check_id}, {f.confidence:.2f})" for f in report.needs_review]
    return "\n".join(lines) + "\n"


@router.get("/scans/{scan_id}/report", tags=["report"], response_model=None)
async def get_report(
    scan_id: UUID,
    services: ServicesDep,
    user: UserDep,
    format: ReportFormat = ReportFormat.JSON,
) -> Report | PlainTextResponse:
    """Report as json or Markdown. PDF is not produced by the API yet (501)."""
    if format is ReportFormat.PDF:
        _error(status.HTTP_501_NOT_IMPLEMENTED, "not_implemented", "pdf export is not available")
    with services.session_factory() as db:
        scan = _scan_or_404(db, scan_id, user)
        rows = db.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id)).all()
        report = Report(
            scan=_detail(scan),
            findings=[_finding(r) for r in rows if not r.needs_review],
            needs_review=[_finding(r) for r in rows if r.needs_review],
        )
    if format is ReportFormat.MD:
        return PlainTextResponse(_report_markdown(report), media_type="text/markdown")
    return report


@router.post("/scans/{scan_id}/approvals", tags=["approvals"])
async def create_approval(
    scan_id: UUID, body: ApprovalRequest, services: ServicesDep, user: UserDep
) -> ApprovalResult:
    """Record a human decision before any outward action (GitHub issue / send report)."""
    with services.session_factory() as db:
        scan = _scan_or_404(db, scan_id, user)
        if scan.status not in (ScanStatus.AWAITING_APPROVAL, ScanStatus.COMPLETED):
            _error(status.HTTP_409_CONFLICT, "not_ready", "the scan has not finished yet")
        already = db.scalar(
            select(Approval.id).where(Approval.scan_id == scan_id, Approval.action == body.action)
        )
        if already is not None:
            _error(status.HTTP_409_CONFLICT, "already_decided", "this action was already decided")
        db.add(Approval(scan_id=scan_id, action=body.action, approved=body.approved))
        old_status = scan.status
        if body.approved and scan.status is ScanStatus.AWAITING_APPROVAL:
            scan.status = ScanStatus.COMPLETED
        new_status = scan.status
        db.commit()
    if new_status is not old_status:
        await services.audit.append(
            AuditEvent(
                ts=utcnow(),
                scan_id=scan_id,
                actor=AuditActor.API,
                action="scan.status",
                target=new_status.value,
                decision=AuditDecision.ALLOWED,
                reason=f"{body.action.value} approved by {user}",
            )
        )
    await services.audit.append(
        AuditEvent(
            ts=utcnow(),
            scan_id=scan_id,
            actor=AuditActor.API,
            action=f"approval.{body.action.value}",
            target=body.action.value,
            decision=AuditDecision.ALLOWED if body.approved else AuditDecision.BLOCKED,
            reason=f"{'approved' if body.approved else 'declined'} by {user}",
        )
    )
    return ApprovalResult(
        scan_id=scan_id, action=body.action, approved=body.approved, scan_status=new_status
    )


@router.get("/scans/{scan_id}/audit", tags=["audit"])
async def get_audit(scan_id: UUID, services: ServicesDep, user: UserDep) -> list[AuditEvent]:
    """Immutable audit log of this scan, oldest first."""
    with services.session_factory() as db:
        _scan_or_404(db, scan_id, user)
    events = await asyncio.to_thread(services.audit_store.events_since, scan_id, -1)
    return [event for _, event in events]


__all__ = ["ApprovalAction", "router"]
