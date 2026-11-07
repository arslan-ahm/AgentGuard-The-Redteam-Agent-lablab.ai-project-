"""Job queue for scans (brief 4: Redis + RQ). Owner: Sohaib.

Two implementations of one tiny interface:

- ``RqQueue``: pushes ``run_scan_job(scan_id)`` onto Redis; a separate worker process
  (``uv run rq worker`` with ``app.orchestrator.worker``) runs it. Used when Redis answers.
- ``InProcessQueue``: runs the scan as a background asyncio task in the API process. This is
  the zero-dependency path for local development and tests.

Both are safe to call twice for one scan: the orchestrator claims a scan atomically, so the
second run is a no-op (idempotent job handling).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Protocol
from uuid import UUID

log = logging.getLogger(__name__)

RunScan = Callable[[UUID], Awaitable[None]]
JOB_PATH = "app.orchestrator.worker.run_scan_job"
QUEUE_NAME = "agentguard"
"""Must equal the queue the deployed worker listens on (``deploy/worker.Dockerfile``:
``rq worker ... agentguard``); a test checks it."""
JOB_TIMEOUT_S = 1800


class JobQueue(Protocol):
    def enqueue_scan(self, scan_id: UUID) -> None: ...


class InProcessQueue:
    """Runs scans as asyncio tasks in the current event loop."""

    def __init__(self, run_scan: RunScan) -> None:
        self._run_scan = run_scan
        self._tasks: set[asyncio.Task[None]] = set()

    async def _run(self, scan_id: UUID) -> None:
        await self._run_scan(scan_id)

    def enqueue_scan(self, scan_id: UUID) -> None:
        task = asyncio.get_running_loop().create_task(self._run(scan_id))
        self._tasks.add(task)  # keep a reference so the task is not garbage collected
        task.add_done_callback(self._tasks.discard)

    async def drain(self) -> None:
        """Wait for running scans (tests and graceful shutdown)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)


class RqQueue:
    """Redis + RQ."""

    def __init__(self, redis_url: str) -> None:
        from redis import Redis
        from rq import Queue

        self._queue = Queue(QUEUE_NAME, connection=Redis.from_url(redis_url))

    def enqueue_scan(self, scan_id: UUID) -> None:
        self._queue.enqueue(JOB_PATH, str(scan_id), job_timeout=JOB_TIMEOUT_S)


def redis_reachable(redis_url: str, timeout_s: float = 0.5) -> bool:
    """True if a Redis server answers PING at ``redis_url``."""
    try:
        from redis import Redis

        return bool(Redis.from_url(redis_url, socket_connect_timeout=timeout_s).ping())
    except Exception:  # connection refused, DNS, bad URL...: fall back to in-process
        return False


def build_queue(redis_url: str, run_scan: RunScan) -> JobQueue:
    """RQ if Redis is up, else the in-process queue (logged, never silent)."""
    if redis_reachable(redis_url):
        log.info("job queue: Redis/RQ")
        return RqQueue(redis_url)
    log.warning("job queue: Redis not reachable, running scans in the API process")
    return InProcessQueue(run_scan)
