"""Shared fixtures for the API and orchestrator tests (no network, no Docker, no Redis)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

import app.api.auth as _auth
from app.api.auth import hash_password
from app.db.models import User
from app.db.session import Base
from app.main import create_app
from app.orchestrator.db_audit import DbAuditStore
from app.orchestrator.fakes import FakePlanner, FakeSandbox
from app.orchestrator.orchestrator import Orchestrator
from app.orchestrator.queue import InProcessQueue
from app.orchestrator.services import Services
from app.policy.audit import HashChainedAuditLog
from app.policy.rate_limit import ScanRateLimiter
from app.policy.url_policy import PolicyBlocked

_auth._SCRYPT_N = 2**4  # tests only: keeps hashing fast; production keeps 2**14

SECRET = "test-secret-key-0123456789abcdef"  # noqa: S105
PASSWORD = "correct horse battery"  # noqa: S105


class StubPolicy:
    """Blocks metadata and ``blocked.example`` URLs; allows everything else (no DNS)."""

    async def assert_allowed(self, url: str) -> None:
        if "169.254" in url or "blocked.example" in url:
            raise PolicyBlocked(url, "address is not publicly routable")


def make_services(tmp_path: Path, **overrides: object) -> Services:
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    factory: sessionmaker[Session] = sessionmaker(
        bind=engine, autoflush=False, expire_on_commit=False
    )
    store = DbAuditStore(factory)
    audit = HashChainedAuditLog(store)
    services = Services(
        session_factory=factory,
        policy=StubPolicy(),
        rate_limiter=ScanRateLimiter(),
        audit=audit,
        audit_store=store,
        planner=FakePlanner(),
        sandbox=FakeSandbox(audit),
        evidence_root=tmp_path / "work",
        secret_key=SECRET,
    )
    for key, value in overrides.items():
        setattr(services, key, value)
    services.queue = InProcessQueue(Orchestrator(services).run_scan)
    with factory() as db:
        db.add(User(email="alice@example.com", password_hash=hash_password(PASSWORD)))
        db.add(User(email="bob@example.com", password_hash=hash_password(PASSWORD)))
        db.commit()
    return services


@pytest.fixture
def services(tmp_path: Path) -> Services:
    return make_services(tmp_path)


@pytest.fixture
def client(services: Services) -> Iterator[TestClient]:
    with TestClient(create_app(services)) as c:
        yield c


def login(client: TestClient, email: str = "alice@example.com") -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def auth(client: TestClient) -> dict[str, str]:
    return login(client)
