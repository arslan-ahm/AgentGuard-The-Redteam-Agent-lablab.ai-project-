"""Database store for Arslan's hash-chained audit log (brief 5.9, 6.9). Owner: Sohaib.

``DbAuditStore`` implements ``app.policy.audit.AuditStore`` on the ``audit_events`` table.
Wrap it in ``HashChainedAuditLog`` to get redaction + chaining. The store has INSERT and SELECT
only: no update or delete method exists, and the ORM rejects them as well.
"""

from __future__ import annotations

import asyncio
import random
import time
from datetime import UTC, datetime
from uuid import UUID

from agentguard_contracts import AuditActor, AuditDecision, AuditEvent
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import AuditEventRow
from app.policy.audit import AuditRecord, next_record

MAX_APPEND_RETRIES = 12
CHAIN_LOCK_KEY = 7_302_001
"""Arbitrary constant: the Postgres advisory-lock id that serialises audit appends."""


def _aware(ts: datetime) -> datetime:
    """SQLite returns naive datetimes; the chain hashes the UTC value that was written."""
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def _event(row: AuditEventRow) -> AuditEvent:
    return AuditEvent(
        ts=_aware(row.ts),
        scan_id=row.scan_id,
        task_id=row.task_id,
        actor=AuditActor(row.actor),
        action=row.action,
        target=row.target,
        decision=AuditDecision(row.decision),
        reason=row.reason,
    )


def _record(row: AuditEventRow) -> AuditRecord:
    return AuditRecord(row.seq, _event(row), row.prev_hash, row.hash)


class DbAuditStore:
    """Audit chain in the SQL database. Safe for several writers (API and workers)."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def _append(self, event: AuditEvent) -> AuditRecord:
        for attempt in range(MAX_APPEND_RETRIES):
            if attempt:  # lost a race: back off a little, with jitter, before re-reading
                time.sleep(random.uniform(0, 0.02 * 2**attempt))  # noqa: S311 (jitter, not crypto)
            with self._session_factory() as session:
                if session.get_bind().dialect.name == "postgresql":
                    # Writers take turns instead of racing for the same ``seq`` (the unique
                    # constraint stays as the backstop). Released when the transaction ends.
                    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": CHAIN_LOCK_KEY})
                last = session.scalars(
                    select(AuditEventRow).order_by(AuditEventRow.seq.desc()).limit(1)
                ).first()
                record = next_record(_record(last) if last else None, event)
                session.add(
                    AuditEventRow(
                        seq=record.seq,
                        prev_hash=record.prev_hash,
                        hash=record.hash,
                        ts=event.ts,
                        scan_id=event.scan_id,
                        task_id=event.task_id,
                        actor=event.actor,
                        action=event.action,
                        target=event.target,
                        decision=event.decision,
                        reason=event.reason,
                    )
                )
                try:
                    session.commit()
                except IntegrityError:
                    continue  # another writer took this seq: re-read and chain on top of it
                return record
        raise RuntimeError("audit append kept colliding; giving up")

    async def append_chained(self, event: AuditEvent) -> AuditRecord:
        return await asyncio.to_thread(self._append, event)

    def _read_all(self) -> list[AuditRecord]:
        with self._session_factory() as session:
            rows = session.scalars(select(AuditEventRow).order_by(AuditEventRow.seq)).all()
            return [_record(r) for r in rows]

    async def read_all(self) -> list[AuditRecord]:
        return await asyncio.to_thread(self._read_all)

    def events_since(self, scan_id: UUID, after_seq: int = -1) -> list[tuple[int, AuditEvent]]:
        """``(seq, event)`` for one scan with ``seq > after_seq``, oldest first."""
        with self._session_factory() as session:
            rows = session.scalars(
                select(AuditEventRow)
                .where(AuditEventRow.scan_id == scan_id, AuditEventRow.seq > after_seq)
                .order_by(AuditEventRow.seq)
            ).all()
            return [(r.seq, _event(r)) for r in rows]
