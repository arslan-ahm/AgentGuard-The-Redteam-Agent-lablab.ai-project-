"""ORM models for scans, tasks, findings, approvals and the audit log (brief 5.2, 5.4, 5.9).

Owner: Sohaib. Column values mirror the frozen contracts in ``agentguard_contracts``; enums are
stored as their string values so the schema stays readable and portable (PostgreSQL and SQLite).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from agentguard_contracts import (
    ApprovalAction,
    AuditActor,
    AuditDecision,
    FindingCategory,
    SandboxResultStatus,
    ScanProfile,
    ScanStatus,
    Severity,
)
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    event,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Mapped, Mapper, mapped_column, relationship

from app.db.session import Base


def utcnow() -> datetime:
    """Timezone-aware UTC now (the single time source for the database layer)."""
    return datetime.now(UTC)


def _enum(enum_cls: type[Any], name: str) -> SAEnum:
    """Store a StrEnum by value as a plain string (no native DB enum: simpler migrations)."""
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        length=32,
        values_callable=lambda e: [m.value for m in e],
        validate_strings=True,
    )


class User(Base):
    """An API user. Only a salted scrypt hash of the password is stored."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scan(Base):
    """One scan of a target URL (brief 5.2 lifecycle)."""

    __tablename__ = "scans"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    owner: Mapped[str] = mapped_column(String(255), default="", index=True)
    containment_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    target_url: Mapped[str] = mapped_column(Text)
    profile: Mapped[ScanProfile] = mapped_column(_enum(ScanProfile, "scan_profile"))
    credentials_ref: Mapped[str | None] = mapped_column(String(255), default=None)
    status: Mapped[ScanStatus] = mapped_column(
        _enum(ScanStatus, "scan_status"), default=ScanStatus.QUEUED, index=True
    )
    plan: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    tasks_total: Mapped[int] = mapped_column(Integer, default=0)
    tasks_done: Mapped[int] = mapped_column(Integer, default=0)
    score: Mapped[int | None] = mapped_column(Integer, default=None)
    recommendation: Mapped[str | None] = mapped_column(String(64), default=None)
    summary: Mapped[str | None] = mapped_column(Text, default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    tasks: Mapped[list[ScanTask]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="ScanTask.position"
    )
    findings: Mapped[list[FindingRow]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    approvals: Mapped[list[Approval]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanTask(Base):
    """One planned task of a scan and, once run, the sandbox outcome (brief 5.5 and 5.6)."""

    __tablename__ = "scan_tasks"
    __table_args__ = (Index("ix_scan_tasks_scan_task", "scan_id", "task_id", unique=True),)

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    task_id: Mapped[str] = mapped_column(String(64))
    position: Mapped[int] = mapped_column(Integer, default=0)
    check_id: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text, default="")
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    timeout_s: Mapped[int] = mapped_column(Integer)
    status: Mapped[SandboxResultStatus | None] = mapped_column(
        _enum(SandboxResultStatus, "task_status"), default=None
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer, default=None)
    policy_events: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    scan: Mapped[Scan] = relationship(back_populates="tasks")


class FindingRow(Base):
    """A finding as stored and served by the API (brief 5.4; ``Finding`` contract)."""

    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    task_id: Mapped[str | None] = mapped_column(String(64), default=None)
    title: Mapped[str] = mapped_column(Text)
    category: Mapped[FindingCategory] = mapped_column(_enum(FindingCategory, "finding_category"))
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"))
    confidence: Mapped[float] = mapped_column(Float)
    url: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[str]] = mapped_column(JSON, default=list)
    reproduction: Mapped[list[str]] = mapped_column(JSON, default=list)
    impact: Mapped[str] = mapped_column(Text)
    recommended_fix: Mapped[str] = mapped_column(Text)
    check_id: Mapped[str] = mapped_column(String(64))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Approval(Base):
    """A human approval decision for an outward action (GitHub issue / send report)."""

    __tablename__ = "approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    action: Mapped[ApprovalAction] = mapped_column(_enum(ApprovalAction, "approval_action"))
    approved: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="approvals")


class AuditEventRow(Base):
    """Append-only audit log (brief 5.9). Updates and deletes are rejected at the ORM level."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Hash chain (``app.policy.audit``): ``seq`` is unique, so two writers racing for the same
    # position cannot both succeed; the loser retries on top of the winner's record.
    seq: Mapped[int] = mapped_column(Integer, unique=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    # Deliberately not a foreign key: audit rows must outlive (and never be cascaded by) a scan.
    scan_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    task_id: Mapped[str | None] = mapped_column(String(64), default=None)
    actor: Mapped[AuditActor] = mapped_column(_enum(AuditActor, "audit_actor"))
    action: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(Text)
    decision: Mapped[AuditDecision] = mapped_column(_enum(AuditDecision, "audit_decision"))
    reason: Mapped[str] = mapped_column(Text)


class AuditImmutableError(RuntimeError):
    """Raised when code tries to update or delete an audit row."""


@event.listens_for(AuditEventRow, "before_update")
@event.listens_for(AuditEventRow, "before_delete")
def _audit_is_append_only(_mapper: Mapper[Any], _conn: Connection, _target: object) -> None:
    raise AuditImmutableError("audit_events is append-only: rows cannot be updated or deleted")
