"""Boundaries between backend modules, taken from the brief. Program against these.

Owners implement them; the orchestrator (Sohaib) only depends on these protocols, so a
fake can stand in until the real module lands (brief 6.2: fake planner, fake sandbox).

The Verifier's call signature is not fixed by the brief yet. Ayesha and Sohaib agree on
it and add it here through a change request.
"""

from __future__ import annotations

from typing import Protocol

from agentguard_contracts import (
    AuditEvent,
    Finding,
    SandboxResult,
    SandboxTaskInput,
    ScanProfile,
    TestPlan,
)


class Planner(Protocol):
    """Agent planner, brief 6.3. Owner: Ayesha. Lives in ``app/agent/``."""

    async def plan(self, target_url: str, profile: ScanProfile) -> TestPlan:
        """Return a validated plan; fall back to the deterministic plan if the LLM fails."""
        ...

    async def summarize(self, findings: list[Finding]) -> str:
        """Executive summary of the findings."""
        ...


class SandboxRunner(Protocol):
    """Orchestration-side sandbox launcher, brief 6.4. Owner: Arslan."""

    async def run(self, task: SandboxTaskInput) -> SandboxResult:
        """Run one task in a fresh, locked-down container and return its ``result.json``."""
        ...


class UrlPolicy(Protocol):
    """URL validation, brief 6.9. Owner: Arslan. Lives in ``app/policy/``."""

    async def assert_allowed(self, url: str) -> None:
        """Raise if ``url`` is not allowed (scheme, private/loopback/metadata IP, credentials)."""
        ...


class AuditSink(Protocol):
    """Append-only audit log, brief 5.9 and 6.9. Owner: Arslan."""

    async def append(self, event: AuditEvent) -> None:
        """Append one event. There is deliberately no update or delete."""
        ...
