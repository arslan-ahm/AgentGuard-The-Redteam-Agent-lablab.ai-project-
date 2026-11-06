"""Verifier hook used by the orchestrator (brief 6.7).

The Verifier's call signature is not fixed by the brief (see ``app/interfaces.py``): Sarah and
Sohaib agree on it through a change request. Until then the orchestrator depends on this small
local protocol and ships a conservative default, so swapping in Sarah's verifier is a one-line
change in ``services.py``.
"""

from __future__ import annotations

from typing import Protocol

from agentguard_contracts import Finding

MIN_CONFIDENCE = 0.5
"""Brief 6.7: findings below this go to the 'needs manual review' bucket."""


class Verifier(Protocol):
    async def verify(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Return ``(confirmed, needs_review)``. Must not invent or drop findings silently."""
        ...


class ConfidenceVerifier:
    """Default: no re-checking, only the brief's confidence rule. ``verified`` stays False
    because nothing was independently re-validated."""

    async def verify(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        confirmed = [f for f in findings if f.confidence >= MIN_CONFIDENCE]
        review = [f for f in findings if f.confidence < MIN_CONFIDENCE]
        return confirmed, review
