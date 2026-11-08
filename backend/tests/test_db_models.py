"""DB models and the initial migration (Sohaib: API + orchestration)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from agentguard_contracts import (
    AuditActor,
    AuditDecision,
    FindingCategory,
    ScanProfile,
    ScanStatus,
    Severity,
)
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from alembic import command
from app.db.models import (
    AuditEventRow,
    AuditImmutableError,
    FindingRow,
    Scan,
    ScanTask,
)
from app.db.session import Base

BACKEND = Path(__file__).resolve().parent.parent


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_scan_defaults_and_relationships(session: Session) -> None:
    scan = Scan(target_url="https://demo.example.com", profile=ScanProfile.FULL)
    scan.tasks.append(
        ScanTask(task_id="t1", check_id="qa.forms", timeout_s=90, params={"path": "/contact"})
    )
    scan.findings.append(
        FindingRow(
            title="Leak",
            category=FindingCategory.SECURITY,
            severity=Severity.HIGH,
            confidence=0.9,
            url="https://demo.example.com/checkout",
            evidence=["screenshot_3.png"],
            reproduction=["Open /checkout"],
            impact="x",
            recommended_fix="y",
            check_id="security.error_leak",
        )
    )
    session.add(scan)
    session.commit()

    loaded = session.get(Scan, scan.id)
    assert loaded is not None
    assert loaded.status is ScanStatus.QUEUED
    assert loaded.created_at is not None
    assert loaded.tasks[0].params == {"path": "/contact"}
    assert loaded.findings[0].verified is False
    assert loaded.findings[0].evidence == ["screenshot_3.png"]


def test_enum_values_are_stored_as_strings(session: Session) -> None:
    scan = Scan(target_url="https://a.example", profile=ScanProfile.SMOKE)
    session.add(scan)
    session.commit()
    raw = session.connection().exec_driver_sql("select profile, status from scans").one()
    assert tuple(raw) == ("smoke", "queued")


def _audit() -> AuditEventRow:
    return AuditEventRow(
        seq=0,
        prev_hash="0" * 64,
        hash="1" * 64,
        scan_id=uuid4(),
        actor=AuditActor.POLICY,
        action="url_check",
        target="http://169.254.169.254",
        decision=AuditDecision.BLOCKED,
        reason="metadata ip",
    )


def test_audit_rows_cannot_be_updated(session: Session) -> None:
    row = _audit()
    session.add(row)
    session.commit()
    row.reason = "tampered"
    with pytest.raises(AuditImmutableError):
        session.commit()


def test_audit_rows_cannot_be_deleted(session: Session) -> None:
    row = _audit()
    session.add(row)
    session.commit()
    session.delete(row)
    with pytest.raises(AuditImmutableError):
        session.commit()


def test_audit_rows_survive_scan_deletion(session: Session) -> None:
    scan = Scan(target_url="https://a.example", profile=ScanProfile.QA)
    session.add(scan)
    session.commit()
    row = _audit()
    row.scan_id = scan.id
    session.add(row)
    session.commit()
    session.delete(scan)
    session.commit()
    assert session.query(AuditEventRow).count() == 1


def _alembic_cfg(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Config:
    from app.config import get_settings

    monkeypatch.setenv("DATABASE_URL", db_url)
    get_settings.cache_clear()
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    return cfg


def test_migration_matches_models_and_downgrades(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.config import get_settings

    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = _alembic_cfg(url, monkeypatch)
    command.upgrade(cfg, "head")

    engine = create_engine(url)
    assert {"scans", "scan_tasks", "findings", "approvals", "audit_events"} <= set(
        inspect(engine).get_table_names()
    )
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], f"models drifted from migration: {diff}"

    command.downgrade(cfg, "base")
    assert "scans" not in inspect(create_engine(url)).get_table_names()
    get_settings.cache_clear()
