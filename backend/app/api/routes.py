"""REST API surface from brief 5.8. Owner: Sohaib (API + orchestration), reviewer: Arslan.

Every route is wired with its contract types and currently answers ``501 not_implemented``
in the 5.8 error shape. Replace each body as the feature lands. Do not add or rename fields;
response models that the brief does not spell out (login token, scan detail) need a CR first.
"""

from __future__ import annotations

from typing import NoReturn
from uuid import UUID

from agentguard_contracts import ApprovalRequest, ReportFormat, ScanCreate, ScanCreated
from fastapi import APIRouter, HTTPException, status

router = APIRouter()


def _not_implemented(what: str) -> NoReturn:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={"code": "not_implemented", "message": f"{what} is not implemented yet"},
    )


@router.post("/auth/login", tags=["auth"])
async def login() -> None:
    """Login, returns a bearer token."""
    _not_implemented("POST /auth/login")


@router.post("/scans", tags=["scans"], status_code=status.HTTP_202_ACCEPTED)
async def create_scan(body: ScanCreate) -> ScanCreated:
    """Create a scan. The policy URL check (Arslan, ``app.policy``) must run before queueing."""
    _not_implemented("POST /scans")


@router.get("/scans", tags=["scans"])
async def list_scans() -> None:
    """List scans."""
    _not_implemented("GET /scans")


@router.get("/scans/{scan_id}", tags=["scans"])
async def get_scan(scan_id: UUID) -> None:
    """Status, progress, score, recommendation."""
    _not_implemented("GET /scans/{id}")


@router.get("/scans/{scan_id}/events", tags=["scans"])
async def scan_events(scan_id: UUID) -> None:
    """SSE stream of progress and audit events."""
    _not_implemented("GET /scans/{id}/events")


@router.get("/scans/{scan_id}/findings", tags=["findings"])
async def list_findings(scan_id: UUID) -> None:
    """List findings (``list[Finding]``)."""
    _not_implemented("GET /scans/{id}/findings")


@router.get("/scans/{scan_id}/evidence/{filename}", tags=["findings"])
async def get_evidence(scan_id: UUID, filename: str) -> None:
    """Serve one evidence file. Must reject path traversal in ``filename``."""
    _not_implemented("GET /scans/{id}/evidence/{filename}")


@router.get("/scans/{scan_id}/report", tags=["report"])
async def get_report(scan_id: UUID, format: ReportFormat = ReportFormat.JSON) -> None:
    """Report export as json, md or pdf."""
    _not_implemented("GET /scans/{id}/report")


@router.post("/scans/{scan_id}/approvals", tags=["approvals"])
async def create_approval(scan_id: UUID, body: ApprovalRequest) -> None:
    """Human approval before a GitHub issue is filed or a report is sent."""
    _not_implemented("POST /scans/{id}/approvals")


@router.get("/scans/{scan_id}/audit", tags=["audit"])
async def get_audit(scan_id: UUID) -> None:
    """Immutable audit log (``list[AuditEvent]``)."""
    _not_implemented("GET /scans/{id}/audit")
