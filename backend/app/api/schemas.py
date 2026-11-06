"""API-only response models for routes whose body the brief does not spell out.

Proposed in ``docs/change-requests/CR-2-api-response-shapes.md``. They live here, not in the
frozen ``agentguard_contracts``, until Arslan and Sarah approve the CR.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from agentguard_contracts import ApprovalAction, Finding, ScanProfile, ScanStatus
from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(_Model):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(_Model):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 (a label, not a secret)
    expires_in: int


class Progress(_Model):
    tasks_total: int
    tasks_done: int


class ScanDetail(_Model):
    """``GET /scans`` rows and ``GET /scans/{id}``: status, progress, score, recommendation."""

    id: UUID
    target_url: str
    profile: ScanProfile
    status: ScanStatus
    progress: Progress
    score: int | None = None
    recommendation: str | None = None
    summary: str | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime


class ApprovalResult(_Model):
    """Outcome of ``POST /scans/{id}/approvals``.

    ``executed`` is False: recording the decision is all this API does. Filing the GitHub
    issue or sending the report is a separate, explicit step that is not wired here yet.
    """

    scan_id: UUID
    action: ApprovalAction
    approved: bool
    scan_status: ScanStatus
    executed: bool = False


class Report(_Model):
    """``GET /scans/{id}/report?format=json``."""

    scan: ScanDetail
    findings: list[Finding]
    needs_review: list[Finding]
