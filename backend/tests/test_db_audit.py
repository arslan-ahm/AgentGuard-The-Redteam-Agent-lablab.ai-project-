"""Concurrent writers on the database audit chain (Sohaib: orchestrator).

Found on real Postgres: 8 concurrent writers made 2 of them give up with "audit append kept
colliding" and 45 events were never stored. Appends now take a Postgres advisory lock.

The Postgres variant runs only when ``AGENTGUARD_TEST_PG_URL`` is set, e.g.::

    docker run -d --rm --name pg -e POSTGRES_USER=ag -e POSTGRES_PASSWORD=agpass \
        -e POSTGRES_DB=ag -p 5440:5432 postgres:16-alpine
    export AGENTGUARD_TEST_PG_URL=postgresql+psycopg://ag:agpass@127.0.0.1:5440/ag
    uv run pytest tests/test_db_audit.py
"""

from __future__ import annotations

import asyncio
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from agentguard_contracts import AuditActor, AuditDecision, AuditEvent
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.orchestrator.db_audit import DbAuditStore
from app.policy.audit import HashChainedAuditLog

WRITERS, EVENTS_EACH = 8, 10


def _hammer(url: str) -> tuple[int, tuple[bool, int | None], list[str]]:
    engine = create_engine(url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    store = DbAuditStore(sessionmaker(bind=engine, expire_on_commit=False))
    audit = HashChainedAuditLog(store)
    errors: list[str] = []

    def work(n: int) -> None:
        async def go() -> None:
            for i in range(EVENTS_EACH):
                await audit.append(
                    AuditEvent(
                        ts=datetime.now(UTC),
                        scan_id=uuid4(),
                        actor=AuditActor.API,
                        action=f"w{n}-{i}",
                        target="t",
                        decision=AuditDecision.ALLOWED,
                        reason="r",
                    )
                )

        try:
            asyncio.run(go())
        except Exception as exc:  # collected so the assertion shows every failure
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=work, args=(n,)) for n in range(WRITERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rows = len(asyncio.run(store.read_all()))
    verdict = asyncio.run(audit.verify())
    engine.dispose()
    return rows, verdict, errors


def test_concurrent_writers_lose_nothing_on_sqlite(tmp_path: Path) -> None:
    rows, verdict, errors = _hammer(f"sqlite:///{tmp_path / 'chain.db'}")
    assert errors == []
    assert rows == WRITERS * EVENTS_EACH
    assert verdict == (True, None)


@pytest.mark.skipif(
    not os.environ.get("AGENTGUARD_TEST_PG_URL"), reason="set AGENTGUARD_TEST_PG_URL (Postgres)"
)
def test_concurrent_writers_lose_nothing_on_postgres() -> None:
    rows, verdict, errors = _hammer(os.environ["AGENTGUARD_TEST_PG_URL"])
    assert errors == []
    assert rows == WRITERS * EVENTS_EACH
    assert verdict == (True, None)
