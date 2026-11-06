"""Hash-chained audit log (brief 5.9, 6.9): append, redact, verify, detect tampering, and stay
consistent when several *processes* append to one log file at the same time."""

from __future__ import annotations

import asyncio
import json
import multiprocessing as mp
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from agentguard_contracts import AuditActor, AuditDecision, AuditEvent

from app.interfaces import AuditSink
from app.policy.audit import (
    GENESIS,
    AuditRecord,
    HashChainedAuditLog,
    InMemoryAuditStore,
    JsonlAuditStore,
    chain_hash,
    verify_chain,
)
from app.policy.redaction import REDACTED

SCAN_A = UUID("0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d")
SCAN_B = UUID("1b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d")


def event(n: int, scan: UUID = SCAN_A, **kw: object) -> AuditEvent:
    data: dict[str, object] = {
        "ts": datetime(2026, 11, 6, 12, 0, n % 60, tzinfo=UTC),
        "scan_id": scan,
        "task_id": f"t{n}",
        "actor": AuditActor.SANDBOX,
        "action": "navigate",
        "target": f"https://shop.example.com/{n}",
        "decision": AuditDecision.ALLOWED,
        "reason": "same origin",
    }
    data.update(kw)
    return AuditEvent.model_validate(data)


def test_log_satisfies_audit_sink() -> None:
    sink: AuditSink = HashChainedAuditLog(InMemoryAuditStore())
    assert sink is not None


async def test_append_builds_valid_chain() -> None:
    store = InMemoryAuditStore()
    log = HashChainedAuditLog(store)
    for n in range(5):
        await log.append(event(n))
    records = await store.read_all()
    assert [r.seq for r in records] == [0, 1, 2, 3, 4]
    assert records[0].prev_hash == GENESIS
    assert all(b.prev_hash == a.hash for a, b in zip(records, records[1:], strict=False))
    assert await log.verify() == (True, None)


async def test_events_filter_by_scan_in_order() -> None:
    log = HashChainedAuditLog(InMemoryAuditStore())
    await log.append(event(1, SCAN_A))
    await log.append(event(2, SCAN_B))
    await log.append(event(3, SCAN_A))
    assert [e.task_id for e in await log.events(SCAN_A)] == ["t1", "t3"]
    assert len(await log.events()) == 3


async def test_secrets_redacted_before_storing() -> None:
    store = InMemoryAuditStore()
    log = HashChainedAuditLog(store)
    await log.append(
        event(
            1,
            target="https://shop.example.com/reset?token=abc123456",
            reason="Authorization: Bearer abcdef0123456789",
            decision=AuditDecision.BLOCKED,
        )
    )
    stored = (await store.read_all())[0].event
    assert stored.target == f"https://shop.example.com/reset?token={REDACTED}"
    assert "abcdef0123456789" not in stored.reason
    assert stored.decision is AuditDecision.BLOCKED


async def test_long_fields_truncated() -> None:
    store = InMemoryAuditStore()
    await HashChainedAuditLog(store).append(event(1, reason="x" * 50_000))
    assert len((await store.read_all())[0].event.reason) == 2000


async def _chain(n: int) -> list[AuditRecord]:
    store = InMemoryAuditStore()
    log = HashChainedAuditLog(store)
    for i in range(n):
        await log.append(event(i))
    return await store.read_all()


async def test_verify_detects_edited_event() -> None:
    records = await _chain(5)
    forged = records[2].event.model_copy(update={"decision": AuditDecision.ALLOWED, "reason": "x"})
    records[2] = AuditRecord(2, forged, records[2].prev_hash, records[2].hash)
    assert verify_chain(records) == (False, 2)


async def test_verify_detects_rehashed_edit() -> None:
    """An attacker who recomputes the edited record's hash still breaks the next link."""
    records = await _chain(5)
    forged = records[2].event.model_copy(update={"reason": "rewritten"})
    records[2] = AuditRecord(
        2, forged, records[2].prev_hash, chain_hash(records[2].prev_hash, forged)
    )
    assert verify_chain(records) == (False, 3)


async def test_verify_detects_deleted_record() -> None:
    records = await _chain(5)
    del records[1]
    assert verify_chain(records) == (False, 2)


async def test_verify_detects_reordering() -> None:
    records = await _chain(5)
    records[1], records[2] = records[2], records[1]
    assert verify_chain(records)[0] is False


async def test_verify_detects_truncated_start() -> None:
    records = await _chain(3)
    assert verify_chain(records[1:]) == (False, 1)


def test_verify_empty_chain_is_valid() -> None:
    assert verify_chain([]) == (True, None)


async def test_concurrent_appends_in_one_process_stay_chained() -> None:
    log = HashChainedAuditLog(InMemoryAuditStore())
    await asyncio.gather(*(log.append(event(i)) for i in range(50)))
    assert await log.verify() == (True, None)
    assert len(await log.events()) == 50


# --- JSONL file store ------------------------------------------------------------------


async def test_jsonl_store_persists_and_resumes(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "audit.jsonl"
    await HashChainedAuditLog(JsonlAuditStore(path)).append(event(1))
    await HashChainedAuditLog(JsonlAuditStore(path)).append(event(2))  # a fresh process
    log = HashChainedAuditLog(JsonlAuditStore(path))
    assert await log.verify() == (True, None)
    assert [e.task_id for e in await log.events()] == ["t1", "t2"]
    lines = path.read_text().splitlines()
    assert [json.loads(line)["seq"] for line in lines] == [0, 1]


async def test_jsonl_tampering_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = HashChainedAuditLog(JsonlAuditStore(path))
    for i in range(3):
        await log.append(event(i, decision=AuditDecision.BLOCKED))
    lines = path.read_text().splitlines()
    lines[1] = lines[1].replace('"blocked"', '"allowed"')
    path.write_text("\n".join(lines) + "\n")
    assert await log.verify() == (False, 1)


async def test_jsonl_long_history_uses_tail(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = HashChainedAuditLog(JsonlAuditStore(path))
    for i in range(300):  # > 64 KB file: the next link must come from the tail read
        await log.append(event(i, reason="r" * 300))
    assert path.stat().st_size > 64 * 1024
    assert await log.verify() == (True, None)


async def test_jsonl_torn_last_line_fails_loudly(tmp_path: Path) -> None:
    """A crash mid-write must not let the next append silently start a fresh chain."""
    path = tmp_path / "audit.jsonl"
    log = HashChainedAuditLog(JsonlAuditStore(path))
    await log.append(event(1))
    with path.open("ab") as fh:
        fh.write(b'{"seq":1,"event":{"ts"')  # torn write, no newline
    with pytest.raises(ValueError):
        await log.append(event(2))
    assert len(path.read_text().splitlines()) == 2  # nothing appended after the torn line


def _worker(path: str, worker: int, count: int) -> None:
    async def go() -> None:
        log = HashChainedAuditLog(JsonlAuditStore(Path(path)))
        for i in range(count):
            await log.append(event(i, task_id=f"w{worker}-{i}"))

    asyncio.run(go())


def test_jsonl_many_processes_one_chain(tmp_path: Path) -> None:
    """API and worker are separate processes: concurrent appends must not fork the chain."""
    path = tmp_path / "shared.jsonl"
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_worker, args=(str(path), w, 15)) for w in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=120)
        assert p.exitcode == 0
    records = asyncio.run(JsonlAuditStore(path).read_all())
    assert len(records) == 60
    assert verify_chain(records) == (True, None)
    assert len({r.event.task_id for r in records}) == 60
