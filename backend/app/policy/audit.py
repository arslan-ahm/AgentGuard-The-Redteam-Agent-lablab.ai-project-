"""Append-only, hash-chained audit log (brief 5.9, 6.9, 12). Owner: Arslan.

``HashChainedAuditLog`` implements ``app.interfaces.AuditSink``. Every event is redacted, then
stored as a record whose ``hash`` covers the event *and* the previous record's hash::

    hash_n = sha256(prev_hash || canonical_json(event_n))      prev_hash_0 = "0" * 64

Changing, deleting, inserting or reordering any stored record breaks every hash after it,
and :func:`verify_chain` reports the first bad sequence number. There is deliberately no
update or delete API. A store needs only an atomic ``append_chained`` and ordered reads: a
JSONL file (here), or a DB table whose role has INSERT/SELECT only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol
from uuid import UUID

from agentguard_contracts import AuditEvent

from app.policy.redaction import redact_text

GENESIS = "0" * 64
MAX_FIELD = 2000
TAIL_BYTES = 64 * 1024


@dataclass(frozen=True)
class AuditRecord:
    """One stored audit entry."""

    seq: int
    event: AuditEvent
    prev_hash: str
    hash: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "seq": self.seq,
                "event": json.loads(self.event.model_dump_json()),
                "prev_hash": self.prev_hash,
                "hash": self.hash,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, line: str) -> AuditRecord:
        data = json.loads(line)
        return cls(
            seq=int(data["seq"]),
            event=AuditEvent.model_validate(data["event"]),
            prev_hash=str(data["prev_hash"]),
            hash=str(data["hash"]),
        )


def canonical(event: AuditEvent) -> bytes:
    """Stable byte form of an event: sorted keys, no whitespace, UTC timestamp as stored."""
    payload = json.loads(event.model_dump_json())
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


def chain_hash(prev_hash: str, event: AuditEvent) -> str:
    return hashlib.sha256(prev_hash.encode() + b"\n" + canonical(event)).hexdigest()


def verify_chain(records: Iterable[AuditRecord]) -> tuple[bool, int | None]:
    """``(True, None)`` if intact, else ``(False, seq of the first broken record)``."""
    expected_prev = GENESIS
    expected_seq = 0
    for record in records:
        if record.seq != expected_seq or record.prev_hash != expected_prev:
            return False, record.seq
        if chain_hash(record.prev_hash, record.event) != record.hash:
            return False, record.seq
        expected_prev = record.hash
        expected_seq += 1
    return True, None


def next_record(last: AuditRecord | None, event: AuditEvent) -> AuditRecord:
    prev_hash = last.hash if last else GENESIS
    seq = last.seq + 1 if last else 0
    return AuditRecord(seq, event, prev_hash, chain_hash(prev_hash, event))


class AuditStore(Protocol):
    """Append-only storage. No update, no delete.

    ``append_chained`` must read the last record, build the next one and write it as one
    atomic step, also across processes (API and worker share the log).
    """

    async def append_chained(self, event: AuditEvent) -> AuditRecord: ...

    async def read_all(self) -> list[AuditRecord]: ...


class InMemoryAuditStore:
    """For tests and local runs without a database."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._lock = asyncio.Lock()

    async def append_chained(self, event: AuditEvent) -> AuditRecord:
        async with self._lock:
            record = next_record(self._records[-1] if self._records else None, event)
            self._records.append(record)
            return record

    async def read_all(self) -> list[AuditRecord]:
        return list(self._records)


class JsonlAuditStore:
    """One JSON record per line. Each append holds an exclusive OS file lock while it reads the
    last record and writes the next, so several processes can share one log safely."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _append_locked(self, event: AuditEvent) -> AuditRecord:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+b") as fh:
            _lock_file(fh)
            try:
                size = fh.seek(0, os.SEEK_END)
                fh.seek(max(0, size - TAIL_BYTES))  # records are < 6 KB: the tail is enough
                last = _last_record(fh.read())
                record = next_record(last, event)
                fh.seek(0, os.SEEK_END)
                fh.write((record.to_json() + "\n").encode())
                fh.flush()
                os.fsync(fh.fileno())
                return record
            finally:
                _unlock_file(fh)

    async def append_chained(self, event: AuditEvent) -> AuditRecord:
        return await asyncio.to_thread(self._append_locked, event)

    def _read(self) -> list[AuditRecord]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as fh:
            return [AuditRecord.from_json(line) for line in fh if line.strip()]

    async def read_all(self) -> list[AuditRecord]:
        return await asyncio.to_thread(self._read)


def _last_record(tail: bytes) -> AuditRecord | None:
    """Last complete record in the file's tail (the first line may be cut, so it's skipped
    unless it is the only line)."""
    lines = [line for line in tail.decode(errors="replace").splitlines() if line.strip()]
    return AuditRecord.from_json(lines[-1]) if lines else None


if sys.platform == "win32":
    import msvcrt

    def _lock_file(fh: BinaryIO) -> None:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)  # retries for ~10 s, then raises

    def _unlock_file(fh: BinaryIO) -> None:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock_file(fh: BinaryIO) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)

    def _unlock_file(fh: BinaryIO) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


class HashChainedAuditLog:
    """``app.interfaces.AuditSink``: redact, chain, append. Safe for concurrent callers."""

    def __init__(self, store: AuditStore) -> None:
        self._store = store

    async def append(self, event: AuditEvent) -> None:
        """Append one event (secrets in ``target``/``reason`` redacted first)."""
        clean = event.model_copy(
            update={
                "target": redact_text(event.target)[:MAX_FIELD],
                "reason": redact_text(event.reason)[:MAX_FIELD],
                "action": event.action[:200],
            }
        )
        await self._store.append_chained(clean)

    async def events(self, scan_id: UUID | None = None) -> list[AuditEvent]:
        """Events in order, optionally for one scan (for ``GET /scans/{id}/audit``)."""
        records = await self._store.read_all()
        return [r.event for r in records if scan_id is None or r.event.scan_id == scan_id]

    async def verify(self) -> tuple[bool, int | None]:
        """Re-check the whole chain."""
        return verify_chain(await self._store.read_all())


def records_from_lines(lines: Sequence[str]) -> list[AuditRecord]:
    return [AuditRecord.from_json(line) for line in lines if line.strip()]
