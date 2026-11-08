"""Release score and recommendation (brief 5.10): re-exported from Sarah's module.

The formula lives in ``app.agent.scoring`` (brief 6.7). This name stays so existing imports
keep working.
"""

from __future__ import annotations

from app.agent.scoring import compute_score, recommend

__all__ = ["compute_score", "recommend"]
