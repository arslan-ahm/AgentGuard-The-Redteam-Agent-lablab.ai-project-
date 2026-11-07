"""Release score and recommendation (brief 5.10).

Sarah owns the real scoring module (brief 6.7). Until it lands, the orchestrator uses this
direct implementation of the frozen 5.10 formula so a scan always ends with a score. When her
function exists, swap the import in ``orchestrator.py``; the formula must stay identical.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from agentguard_contracts import SEVERITY_WEIGHTS, Recommendation, Severity


def compute_score(severities: Iterable[Severity]) -> int:
    """``100 - 25*critical - 12*high - 5*medium - 1*low``, never below 0."""
    counts = Counter(severities)
    penalty = sum(SEVERITY_WEIGHTS[sev] * n for sev, n in counts.items())
    return max(0, 100 - penalty)


def recommend(score: int) -> Recommendation:
    """0-49 block, 50-79 fix first, 80-100 safe to ship."""
    if score < 50:
        return Recommendation.BLOCK
    if score < 80:
        return Recommendation.FIX_FIRST
    return Recommendation.SAFE
