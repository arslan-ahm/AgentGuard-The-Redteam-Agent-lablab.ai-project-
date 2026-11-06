"""RQ worker entry point: ``rq worker agentguard`` runs jobs that call ``run_scan_job``."""

from __future__ import annotations

import asyncio
from uuid import UUID

from app.orchestrator.orchestrator import Orchestrator
from app.orchestrator.services import build_services


def run_scan_job(scan_id: str) -> None:
    """Run one scan to completion in this process (called by RQ)."""
    orchestrator = Orchestrator(build_services())
    asyncio.run(orchestrator.run_scan(UUID(scan_id)))
