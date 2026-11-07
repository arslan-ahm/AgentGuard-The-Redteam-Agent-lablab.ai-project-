"""Wiring: builds every collaborator the API and the worker need. Owner: Sohaib.

Real modules are used by default: Arslan's ``UrlValidator``, ``ScanRateLimiter``,
``HashChainedAuditLog`` (on the SQL database) and ``DockerSandboxRunner``. The planner is
Sarah's; until her module lands the ``FakePlanner`` is used. Fakes for the sandbox too are
opt-in only: set ``AGENTGUARD_USE_FAKES=1`` (local development without Docker). They are never
chosen silently.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, get_settings
from app.interfaces import AuditSink, Planner, SandboxRunner, UrlPolicy
from app.orchestrator.db_audit import DbAuditStore
from app.orchestrator.fakes import FakePlanner, FakeSandbox
from app.orchestrator.queue import JobQueue
from app.orchestrator.verify import ConfidenceVerifier, Verifier
from app.policy.audit import HashChainedAuditLog
from app.policy.rate_limit import ScanRateLimiter, SlidingWindow
from app.policy.url_policy import UrlValidator

log = logging.getLogger(__name__)

DEFAULT_WORK_ROOT = "./.agentguard-work"


@dataclass
class Services:
    session_factory: sessionmaker[Session]
    policy: UrlPolicy
    rate_limiter: ScanRateLimiter
    audit: HashChainedAuditLog
    audit_store: DbAuditStore
    planner: Planner
    sandbox: SandboxRunner
    evidence_root: Path
    secret_key: str
    verifier: Verifier = field(default_factory=ConfidenceVerifier)
    queue: JobQueue | None = None
    login_limiter: SlidingWindow = field(default_factory=lambda: SlidingWindow(10, 300.0))
    """Failed logins per (client address, email): 10 per 5 minutes. Keyed by address too, so
    a stranger cannot lock a user out of their own account from somewhere else."""
    login_ip_limiter: SlidingWindow = field(default_factory=lambda: SlidingWindow(40, 300.0))
    """Failed logins from one client address across all emails: 40 per 5 minutes."""


def use_fakes() -> bool:
    return os.environ.get("AGENTGUARD_USE_FAKES", "").lower() in {"1", "true", "yes"}


def build_services(settings: Settings | None = None) -> Services:
    """Production wiring from environment-backed settings (brief 5.12)."""
    settings = settings or get_settings()
    url = settings.database_url
    engine = create_engine(url, pool_pre_ping=True)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    store = DbAuditStore(session_factory)
    audit = HashChainedAuditLog(store)
    policy = UrlValidator()
    work_root = Path(os.environ.get("AGENTGUARD_WORK_ROOT", DEFAULT_WORK_ROOT))

    sandbox: SandboxRunner
    if use_fakes():
        log.warning("AGENTGUARD_USE_FAKES is set: fake planner and fake sandbox in use")
        sandbox = FakeSandbox(audit)
    else:
        from app.sandbox.launcher import DockerSandboxRunner, SandboxLimits

        sandbox = DockerSandboxRunner(
            image=settings.sandbox_image,
            work_root=work_root,
            limits=SandboxLimits(
                cpus=settings.sandbox_cpu_limit,
                memory=settings.sandbox_mem_limit,
                max_wall_s=settings.sandbox_timeout_s,
            ),
            policy=policy,
            audit=audit,
        )

    if not use_fakes():
        # Sarah's planner (app/agent) does not exist yet, so real scans are planned by the
        # deterministic fake plan. Say so loudly instead of looking like the real thing.
        log.warning("NO REAL PLANNER: scans use FakePlanner (fixed plan per profile)")

    return Services(
        session_factory=session_factory,
        policy=policy,
        rate_limiter=ScanRateLimiter(),
        audit=audit,
        audit_store=store,
        planner=FakePlanner(),  # replaced by Sarah's planner when app/agent provides one
        sandbox=sandbox,
        evidence_root=work_root,
        secret_key=settings.secret_key.get_secret_value(),
    )


__all__ = ["AuditSink", "Services", "build_services", "use_fakes"]
