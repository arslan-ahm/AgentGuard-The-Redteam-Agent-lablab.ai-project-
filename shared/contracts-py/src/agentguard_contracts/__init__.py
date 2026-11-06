"""Frozen AgentGuard contracts: PROJECT_BRIEF.md section 5.

Single Python source of truth for the backend and the sandbox worker. Do not change
anything here without an approved change request (brief section 8, Arslan AND Ayesha).
The TypeScript mirror lives in ``frontend/src/api/contracts.ts`` and must change with it.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class _Frozen(BaseModel):
    """Base for contract models: unknown fields are rejected (never invent API fields)."""

    model_config = ConfigDict(extra="forbid")


# 5.1 – 5.3 enums ---------------------------------------------------------------------


class ScanProfile(StrEnum):
    """5.1 scan profile."""

    SMOKE = "smoke"
    QA = "qa"
    SECURITY = "security"
    FULL = "full"


class ScanStatus(StrEnum):
    """5.2 scan status."""

    QUEUED = "queued"
    PLANNING = "planning"
    RUNNING = "running"
    VERIFYING = "verifying"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class Severity(StrEnum):
    """5.3 severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingCategory(StrEnum):
    """5.4 finding category."""

    QA = "qa"
    SECURITY = "security"
    ACCESSIBILITY = "accessibility"


# 5.4 Finding ---------------------------------------------------------------------------


class FindingDraft(_Frozen):
    """A finding as produced by a check module / sandbox (5.4 without ``id`` and ``scan_id``)."""

    title: str = Field(min_length=1)
    category: FindingCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    url: str
    evidence: list[str]
    reproduction: list[str]
    impact: str
    recommended_fix: str
    check_id: str = Field(pattern=r"^[a-z]+\.[a-z0-9_]+$")
    verified: bool = False


class Finding(FindingDraft):
    """5.4 Finding: the core data model as stored and served by the API."""

    id: UUID
    scan_id: UUID


# 5.5 Test plan -------------------------------------------------------------------------


class PlanTask(_Frozen):
    """One task of a 5.5 test plan."""

    task_id: str = Field(min_length=1)
    check_id: str = Field(pattern=r"^[a-z]+\.[a-z0-9_]+$")
    description: str
    params: dict[str, Any] = Field(default_factory=dict)
    timeout_s: int = Field(gt=0)


class TestPlan(_Frozen):
    """5.5 test plan (Planner -> Orchestrator -> Sandbox)."""

    __test__ = False  # not a pytest test class

    scan_id: UUID
    target_url: str
    profile: ScanProfile
    tasks: list[PlanTask]


MAX_TASKS_PER_PROFILE: Final[dict[ScanProfile, int]] = {
    ScanProfile.SMOKE: 5,
    ScanProfile.QA: 12,
    ScanProfile.SECURITY: 12,
    ScanProfile.FULL: 20,
}
"""Brief 6.3: maximum task count per profile."""

QA_CHECK_IDS: Final[frozenset[str]] = frozenset(
    f"qa.{name}"
    for name in (
        "pages_load",
        "links_assets",
        "forms",
        "login",
        "password_reset",
        "search",
        "checkout",
        "console_network_errors",
        "accessibility",
    )
)
"""Brief 6.5: QA check modules (``sandbox-worker/checks/qa/<name>.py``)."""

SECURITY_CHECK_IDS: Final[frozenset[str]] = frozenset(
    f"security.{name}"
    for name in (
        "https_redirect",
        "headers",
        "cookies",
        "url_session_leak",
        "error_leak",
        "open_redirect",
        "reflected_input",
        "exposed_endpoints",
        "login_rate_probe",
    )
)
"""Brief 6.6: security check modules (``sandbox-worker/checks/security/<name>.py``)."""

ALLOWED_CHECK_IDS: Final[frozenset[str]] = QA_CHECK_IDS | SECURITY_CHECK_IDS
"""Whitelist of check ids a plan may contain (brief 6.3)."""


# 5.6 Sandbox task I/O ------------------------------------------------------------------


class SandboxTaskInput(_Frozen):
    """Contents of ``/in/task.json``: the task plus target_url and scan_id (5.6)."""

    scan_id: UUID
    target_url: str
    task: PlanTask


class SandboxResultStatus(StrEnum):
    """5.6 ``result.json`` status."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    BLOCKED = "blocked"


class SandboxResult(_Frozen):
    """5.6 ``/out/result.json``."""

    task_id: str
    status: SandboxResultStatus
    findings: list[FindingDraft]
    duration_ms: int = Field(ge=0)
    policy_events: list[dict[str, Any]]


class SandboxExitCode:
    """5.6 sandbox process exit codes."""

    OK: Final = 0
    CHECK_ERROR: Final = 2
    POLICY_VIOLATION: Final = 3


# 5.8 REST API --------------------------------------------------------------------------

API_PREFIX: Final = "/api/v1"


class ScanCreate(_Frozen):
    """Body of ``POST /scans``."""

    target_url: str
    profile: ScanProfile
    credentials_ref: str | None = None


class ScanCreated(_Frozen):
    """Response of ``POST /scans``."""

    id: UUID
    status: ScanStatus


class ApprovalAction(StrEnum):
    """``POST /scans/{id}/approvals`` action."""

    GITHUB_ISSUE = "github_issue"
    SEND_REPORT = "send_report"


class ApprovalRequest(_Frozen):
    """Body of ``POST /scans/{id}/approvals``."""

    action: ApprovalAction
    approved: bool


class ReportFormat(StrEnum):
    """``GET /scans/{id}/report?format=``."""

    JSON = "json"
    MD = "md"
    PDF = "pdf"


class ErrorDetail(_Frozen):
    code: str
    message: str


class ErrorResponse(_Frozen):
    """5.8 error shape: ``{"error": {"code", "message"}}``."""

    error: ErrorDetail


# 5.9 Audit event -----------------------------------------------------------------------


class AuditActor(StrEnum):
    API = "api"
    AGENT = "agent"
    SANDBOX = "sandbox"
    POLICY = "policy"


class AuditDecision(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


class AuditEvent(_Frozen):
    """5.9 audit event. Append-only: never updated or deleted."""

    ts: datetime
    scan_id: UUID
    task_id: str | None = None
    actor: AuditActor
    action: str
    target: str
    decision: AuditDecision
    reason: str


# 5.10 Release score --------------------------------------------------------------------

SEVERITY_WEIGHTS: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
}
"""5.10: ``score = max(0, 100 - sum(weight * count))``. The scoring function itself is
owned by the Verifier + scoring module (Ayesha)."""


class Recommendation(StrEnum):
    """5.10 release recommendation text."""

    BLOCK = "Block release"
    FIX_FIRST = "Fix high-priority issues before release"
    SAFE = "Safe to ship with monitoring"


__all__ = [
    "ALLOWED_CHECK_IDS",
    "API_PREFIX",
    "MAX_TASKS_PER_PROFILE",
    "QA_CHECK_IDS",
    "SECURITY_CHECK_IDS",
    "SEVERITY_WEIGHTS",
    "ApprovalAction",
    "ApprovalRequest",
    "AuditActor",
    "AuditDecision",
    "AuditEvent",
    "ErrorDetail",
    "ErrorResponse",
    "Finding",
    "FindingCategory",
    "FindingDraft",
    "PlanTask",
    "Recommendation",
    "ReportFormat",
    "SandboxExitCode",
    "SandboxResult",
    "SandboxResultStatus",
    "SandboxTaskInput",
    "ScanCreate",
    "ScanCreated",
    "ScanProfile",
    "ScanStatus",
    "Severity",
    "TestPlan",
]
