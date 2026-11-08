"""Release score and recommendation (brief 5.10). Pure functions, no I/O. Owner: Sarah.

``score = max(0, 100 - 25*critical - 12*high - 5*medium - 1*low)``
``0-49 -> Block release``, ``50-79 -> Fix high-priority issues before release``,
``80-100 -> Safe to ship with monitoring``.

Only confirmed findings count: the orchestrator passes the verifier's confirmed list, so
"needs manual review" items never move the score.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from agentguard_contracts import SEVERITY_WEIGHTS, Recommendation, Severity

BLOCK_BELOW = 50
SAFE_FROM = 80


def compute_score(severities: Iterable[Severity]) -> int:
    """``100 - 25*critical - 12*high - 5*medium - 1*low``, never below 0."""
    counts = Counter(severities)
    penalty = sum(SEVERITY_WEIGHTS[sev] * n for sev, n in counts.items())
    return max(0, 100 - penalty)


def recommend(score: int) -> Recommendation:
    """0-49 block, 50-79 fix first, 80-100 safe to ship."""
    if not 0 <= score <= 100:
        raise ValueError(f"score must be 0-100, got {score}")
    if score < BLOCK_BELOW:
        return Recommendation.BLOCK
    if score < SAFE_FROM:
        return Recommendation.FIX_FIRST
    return Recommendation.SAFE


@dataclass(frozen=True)
class ScoreBreakdown:
    """Score, recommendation and the counts behind them (for the report)."""

    score: int
    recommendation: Recommendation
    counts: dict[Severity, int]
    penalty: int


def score_breakdown(severities: Iterable[Severity]) -> ScoreBreakdown:
    counts = Counter(severities)
    full = {sev: counts.get(sev, 0) for sev in Severity}
    penalty = sum(SEVERITY_WEIGHTS[sev] * n for sev, n in full.items())
    score = max(0, 100 - penalty)
    return ScoreBreakdown(score, recommend(score), full, penalty)
